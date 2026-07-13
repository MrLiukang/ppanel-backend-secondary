package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/perfect-panel/server/internal/logic/nodeconfig"
	"github.com/perfect-panel/server/internal/model/node"
	"github.com/perfect-panel/server/internal/repository"
	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
	"github.com/perfect-panel/server/pkg/logger"
	"github.com/perfect-panel/server/pkg/xerr"
	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var relaySubscriptionServerLocks sync.Map
var errRelaySubscriptionRevisionMismatch = errors.New("relay subscription group revision mismatch")

const relayPreviewTokenTTL = 5 * time.Minute

type relayPreviewTokenBinding struct {
	GroupID         int64  `json:"group_id"`
	URL             string `json:"url"`
	ListenPortStart int    `json:"listen_port_start"`
	ListenPortStep  int    `json:"listen_port_step"`
	Revision        string `json:"revision"`
	RulesDigest     string `json:"rules_digest"`
}

type RelaySubscriptionGroupLogic struct {
	logger.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewRelaySubscriptionGroupLogic(ctx context.Context, svcCtx *svc.ServiceContext) *RelaySubscriptionGroupLogic {
	return &RelaySubscriptionGroupLogic{Logger: logger.WithContext(ctx), ctx: ctx, svcCtx: svcCtx}
}

func (l *RelaySubscriptionGroupLogic) List(serverID int64) (*types.RelaySubscriptionGroupListResponse, error) {
	var rows []node.RelaySubscriptionGroup
	db := l.svcCtx.Store.DB().WithContext(l.ctx).Where("server_id = ?", serverID)
	var total int64
	if err := db.Model(&node.RelaySubscriptionGroup{}).Count(&total).Error; err != nil {
		return nil, err
	}
	if err := db.Order("id desc").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]types.RelaySubscriptionGroup, 0, len(rows))
	for _, row := range rows {
		result = append(result, relaySubscriptionGroupResponse(row))
	}
	return &types.RelaySubscriptionGroupListResponse{List: result, Total: total}, nil
}

func (l *RelaySubscriptionGroupLogic) Save(req *types.RelaySubscriptionGroupRequest) error {
	unlock := lockRelaySubscriptionServer(req.ServerID)
	defer unlock()
	if _, err := l.svcCtx.Store.Node().FindOneServer(l.ctx, req.ServerID); err != nil {
		return errors.Wrapf(xerr.NewErrCode(xerr.DatabaseQueryError), "find server error: %v", err)
	}
	if req.UpdateInterval <= 0 {
		req.UpdateInterval = 86400
	}
	if req.ListenPortStart <= 0 {
		req.ListenPortStart = 643
	}
	if req.ListenPortStep <= 0 {
		req.ListenPortStep = 100
	}
	if err := validateRelaySubscriptionRequest(req.AutoUpdate, req.URL); err != nil {
		return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
	}
	clearCache := false
	err := l.svcCtx.Store.InTx(l.ctx, func(store repository.Store) error {
		db := store.DB().WithContext(l.ctx)
		if err := lockRelaySubscriptionServerRow(db, req.ServerID); err != nil {
			return err
		}
		if req.Id == 0 {
			return db.Create(&node.RelaySubscriptionGroup{ServerId: req.ServerID, Name: req.Name, URL: req.URL, Enabled: req.Enabled, AutoUpdate: req.AutoUpdate, UpdateInterval: req.UpdateInterval, ListenPortStart: req.ListenPortStart, ListenPortStep: req.ListenPortStep, Rules: "[]", LastStatus: "never"}).Error
		}
		var row node.RelaySubscriptionGroup
		if err := db.Where("id = ? AND server_id = ?", req.Id, req.ServerID).First(&row).Error; err != nil {
			return err
		}
		wasEnabled := row.Enabled
		row.Name, row.URL, row.Enabled, row.AutoUpdate = req.Name, req.URL, req.Enabled, req.AutoUpdate
		row.UpdateInterval, row.ListenPortStart, row.ListenPortStep = req.UpdateInterval, req.ListenPortStart, req.ListenPortStep
		if err := db.Save(&row).Error; err != nil {
			return err
		}
		deleteNodes, rebuild := relayGroupTransition(wasEnabled, row.Enabled)
		if deleteNodes {
			clearCache = true
			if err := deleteRelayGroupNodesTx(db, req.ServerID, row.Id, nil); err != nil {
				return err
			}
			return l.rebuildRelayRulesTx(db, req.ServerID)
		}
		if rebuild {
			clearCache = true
			return l.rebuildRelayRulesTx(db, req.ServerID)
		}
		return nil
	})
	if err != nil || !clearCache {
		return err
	}
	return l.clearServerNodeCache(req.ServerID)
}

func relayGroupTransition(wasEnabled, enabled bool) (deleteNodes, rebuild bool) {
	return wasEnabled && !enabled, wasEnabled != enabled
}

func (l *RelaySubscriptionGroupLogic) Delete(id, serverID int64) error {
	unlock := lockRelaySubscriptionServer(serverID)
	defer unlock()
	err := l.svcCtx.Store.InTx(l.ctx, func(store repository.Store) error {
		db := store.DB().WithContext(l.ctx)
		if err := lockRelaySubscriptionServerRow(db, serverID); err != nil {
			return err
		}
		result := db.Where("id = ? AND server_id = ?", id, serverID).Delete(&node.RelaySubscriptionGroup{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		if err := deleteRelayGroupNodesTx(db, serverID, id, nil); err != nil {
			return err
		}
		return l.rebuildRelayRulesTx(db, serverID)
	})
	if err != nil {
		return err
	}
	return l.clearServerNodeCache(serverID)
}

func (l *RelaySubscriptionGroupLogic) Preview(id, serverID int64) (*types.SubscriptionRelayPreviewResponse, error) {
	var row node.RelaySubscriptionGroup
	if err := l.svcCtx.Store.DB().WithContext(l.ctx).Where("id = ? AND server_id = ?", id, serverID).First(&row).Error; err != nil {
		return nil, err
	}
	resp, err := FetchSubscriptionRelayPreview(l.ctx, row.URL, SubscriptionRelayImportOptions{ListenPortStart: row.ListenPortStart, ListenPortStep: row.ListenPortStep})
	if err != nil {
		return nil, err
	}
	binding, err := relayPreviewBinding(row, resp.Rules)
	if err != nil {
		return nil, err
	}
	resp.PreviewToken, err = signRelayPreviewToken(l.svcCtx.Config.Node.NodeSecret, binding, time.Now())
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (l *RelaySubscriptionGroupLogic) Apply(req *types.RelaySubscriptionGroupApplyRequest, serverID int64) error {
	unlock := lockRelaySubscriptionServer(serverID)
	defer unlock()
	err := l.svcCtx.Store.InTx(l.ctx, func(store repository.Store) error {
		db := store.DB().WithContext(l.ctx)
		if err := lockRelaySubscriptionServerRow(db, serverID); err != nil {
			return err
		}
		var row node.RelaySubscriptionGroup
		if err := db.Where("id = ? AND server_id = ?", req.Id, serverID).First(&row).Error; err != nil {
			return err
		}
		binding, err := relayPreviewBinding(row, req.Rules)
		if err != nil {
			return err
		}
		if err := verifyRelayPreviewToken(l.svcCtx.Config.Node.NodeSecret, req.PreviewToken, binding, time.Now()); err != nil {
			return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
		}
		if err := validateSubscriptionRuntimeRules(req.Rules); err != nil {
			return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
		}
		var oldRules []types.NodeRelayRule
		if err := json.Unmarshal([]byte(row.Rules), &oldRules); err != nil {
			return err
		}
		occupiedPorts, err := l.serverSidecarPorts(db, serverID, row.Id)
		if err != nil {
			return err
		}
		assignedRules, err := assignSidecarPorts(req.Rules, oldRules, occupiedPorts)
		if err != nil {
			return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
		}
		if err := nodeconfig.ValidateRelayRules(sidecarRelayRules(assignedRules, row.Id)); err != nil {
			return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
		}
		rules, err := json.Marshal(assignedRules)
		if err != nil {
			return err
		}
		row.Rules, row.LastStatus, row.LastError = string(rules), "pending", ""
		if err := db.Save(&row).Error; err != nil {
			return err
		}
		currentRuleIDs := make(map[string]struct{}, len(assignedRules))
		for _, rule := range assignedRules {
			if rule.ID != "" {
				currentRuleIDs[rule.ID] = struct{}{}
			}
		}
		if err := deleteRelayGroupNodesTx(db, serverID, row.Id, currentRuleIDs); err != nil {
			return err
		}
		if err := l.rebuildRelayRulesTx(db, serverID); err != nil {
			return err
		}
		now := time.Now()
		return db.Model(&row).Updates(applyStatusValues(nil, now)).Error
	})
	if err != nil {
		statusErr := l.svcCtx.Store.DB().WithContext(l.ctx).Model(&node.RelaySubscriptionGroup{}).
			Where("id = ? AND server_id = ?", req.Id, serverID).Updates(applyStatusValues(err, time.Time{})).Error
		if statusErr != nil {
			return errors.Wrapf(err, "record apply failure: %v", statusErr)
		}
		return err
	}
	return l.clearServerNodeCache(serverID)
}

func (l *RelaySubscriptionGroupLogic) SyncHealthyNodes(serverID int64, req *types.RelaySubscriptionGroupHealthRequest) error {
	unlock := lockRelaySubscriptionServer(serverID)
	defer unlock()
	server, err := l.svcCtx.Store.Node().FindOneServer(l.ctx, serverID)
	if err != nil {
		return err
	}
	publicProtocol := ""
	if protocols, protocolErr := server.UnmarshalProtocols(); protocolErr == nil {
		for _, protocol := range protocols {
			if protocol.Enable {
				publicProtocol = strings.ToLower(protocol.Type)
				break
			}
		}
	}
	var row node.RelaySubscriptionGroup
	db := l.svcCtx.Store.DB().WithContext(l.ctx)
	err = l.svcCtx.Store.InTx(l.ctx, func(store repository.Store) error {
		tx := store.DB().WithContext(l.ctx)
		if err := lockRelaySubscriptionServerRow(tx, serverID); err != nil {
			return err
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND server_id = ?", req.GroupID, serverID).First(&row).Error; err != nil {
			return err
		}
		if err := validateRelayGroupHealthEnabled(row.Enabled); err != nil {
			return err
		}
		var rules []types.NodeRelayRule
		if err := json.Unmarshal([]byte(row.Rules), &rules); err != nil {
			return err
		}
		return withCurrentRelayRevision(rules, req.Revision, func() error {
			results, err := currentHealthResults(rules, req.Results)
			if err != nil {
				return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
			}
			var allNodes []node.Node
			if err := tx.Where("server_id = ?", serverID).Find(&allNodes).Error; err != nil {
				return err
			}
			usedNames := make(map[string]struct{}, len(allNodes))
			for _, item := range allNodes {
				if !relayNodeBelongsToGroup(item, req.GroupID) {
					usedNames[item.Name] = struct{}{}
				}
			}
			for _, rule := range rules {
				if rule.ID == "" {
					continue
				}
				result, reported := results[rule.ID]
				if !reported || !rule.Enabled || !result.Healthy {
					if err := disableUnhealthyRelayNode(tx, serverID, req.GroupID, rule.ID); err != nil {
						return err
					}
					continue
				}
				var existing node.Node
				err := tx.Where("server_id = ? AND relay_group_id = ? AND relay_rule_id = ?", serverID, req.GroupID, rule.ID).First(&existing).Error
				nameBase := strings.TrimSpace(rule.Remark)
				if nameBase == "" {
					nameBase = strings.TrimSpace(row.Name)
				}
				name := uniqueRelayNodeName(nameBase, usedNames)
				if errors.Is(err, gorm.ErrRecordNotFound) {
					protocol := publicProtocol
					if protocol == "" {
						protocol = strings.ToLower(rule.TargetProtocol)
					}
					existing = node.Node{Name: name, RelayGroupId: relayGroupIDPtr(req.GroupID), RelayRuleId: rule.ID, Port: uint16(rule.ListenPort), Address: server.Address, ServerId: serverID, Protocol: protocol, Enabled: boolPtr(true)}
					if err := tx.Create(&existing).Error; err != nil {
						return err
					}
					usedNames[name] = struct{}{}
					continue
				}
				if err != nil {
					return err
				}
				protocol := publicProtocol
				if protocol == "" {
					protocol = strings.ToLower(rule.TargetProtocol)
				}
				syncRelayNodeManagedFields(&existing, rule.ListenPort, server.Address, protocol)
				if err := tx.Save(&existing).Error; err != nil {
					return err
				}
				usedNames[existing.Name] = struct{}{}
			}
			status, statusError := relayGroupHealthStatus(rules, results)
			if err := tx.Model(&row).Updates(map[string]any{"last_status": status, "last_error": statusError}).Error; err != nil {
				return err
			}
			return l.rebuildRelayRulesTx(tx, serverID)
		})
	})
	if err != nil {
		if !shouldRecordRelayHealthFailure(err) {
			return err
		}
		if statusErr := db.Model(&row).Updates(applyStatusValues(err, time.Time{})).Error; statusErr != nil {
			return errors.Wrapf(err, "record health failure: %v", statusErr)
		}
		return err
	}
	return l.clearServerNodeCache(serverID)
}

func (l *RelaySubscriptionGroupLogic) rebuildRelayRulesTx(db *gorm.DB, serverID int64) error {
	var groups []node.RelaySubscriptionGroup
	if err := db.Where("server_id = ? AND enabled = ?", serverID, true).Order("id asc").Find(&groups).Error; err != nil {
		return err
	}
	groupRules := make(map[int64][]types.NodeRelayRule, len(groups))
	for _, group := range groups {
		var rules []types.NodeRelayRule
		if err := json.Unmarshal([]byte(group.Rules), &rules); err != nil {
			return err
		}
		groupRules[group.Id] = rules
	}
	var stored node.ServerConfigOverride
	err := db.Where("server_id = ?", serverID).First(&stored).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	var storedPtr *node.ServerConfigOverride
	if err == nil {
		storedPtr = &stored
	}
	override, err := nodeconfig.OverrideResponse(storedPtr)
	if err != nil {
		return err
	}
	existing := override.RelayRules
	if override.InheritRelayRules {
		existing = nodeconfig.GlobalValues(l.svcCtx.Config.Node).RelayRules
	}
	override.InheritRelayRules = false
	override.RelayRules, err = mergeSubscriptionRelayRules(existing, groupRules)
	if err != nil {
		return err
	}
	model, allInherited, err := nodeconfig.OverrideModel(serverID, override)
	if err != nil {
		return err
	}
	if allInherited {
		return db.Where("server_id = ?", serverID).Delete(&node.ServerConfigOverride{}).Error
	}
	if storedPtr != nil {
		model.Id, model.CreatedAt = stored.Id, stored.CreatedAt
	}
	return db.Save(model).Error
}

func applyStatusValues(applyErr error, completedAt time.Time) map[string]any {
	if applyErr != nil {
		return map[string]any{"last_status": "error", "last_error": applyErr.Error()}
	}
	return map[string]any{"last_status": "success", "last_error": "", "last_updated_at": &completedAt}
}

func deleteRelayGroupNodesTx(db *gorm.DB, serverID, groupID int64, currentRuleIDs map[string]struct{}) error {
	var nodes []node.Node
	if err := db.Where("server_id = ?", serverID).Find(&nodes).Error; err != nil {
		return err
	}
	for _, item := range nodes {
		if currentRuleIDs == nil {
			if !relayNodeBelongsToGroup(item, groupID) {
				continue
			}
		} else if !relayNodeIsOrphaned(item, groupID, currentRuleIDs) {
			continue
		}
		if err := db.Delete(&item).Error; err != nil {
			return err
		}
	}
	return nil
}

func lockRelaySubscriptionServer(serverID int64) func() {
	value, _ := relaySubscriptionServerLocks.LoadOrStore(serverID, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func lockRelaySubscriptionServerRow(db *gorm.DB, serverID int64) error {
	var server node.Server
	return db.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").Where("id = ?", serverID).First(&server).Error
}

func (l *RelaySubscriptionGroupLogic) clearServerNodeCache(serverID int64) error {
	return l.svcCtx.Store.Node().ClearServerCache(l.ctx, serverID)
}

func boolPtr(value bool) *bool           { return &value }
func relayGroupIDPtr(value int64) *int64 { return &value }

func validateRelayGroupHealthEnabled(enabled bool) error {
	if !enabled {
		return xerr.NewErrCodeMsg(xerr.InvalidParams, "disabled relay subscription group cannot accept health results")
	}
	return nil
}

func syncRelayNodeManagedFields(existing *node.Node, listenPort int, address, protocol string) {
	existing.Port = uint16(listenPort)
	existing.Address = address
	existing.Protocol = protocol
	existing.Enabled = boolPtr(true)
}

func relayNodeBelongsToGroup(item node.Node, groupID int64) bool {
	return item.RelayGroupId != nil && *item.RelayGroupId == groupID
}

func relayNodeMatchesGroupRule(item node.Node, groupID int64, ruleID string) bool {
	return relayNodeBelongsToGroup(item, groupID) && item.RelayRuleId == ruleID
}

func findRelayGroupNode(db *gorm.DB, serverID, groupID int64, ruleID string, result *node.Node) error {
	var nodes []node.Node
	if err := db.Where("server_id = ?", serverID).Find(&nodes).Error; err != nil {
		return err
	}
	for _, item := range nodes {
		if relayNodeMatchesGroupRule(item, groupID, ruleID) {
			*result = item
			return nil
		}
	}
	return gorm.ErrRecordNotFound
}

func disableUnhealthyRelayNode(db *gorm.DB, serverID, groupID int64, ruleID string) error {
	var existing node.Node
	err := findRelayGroupNode(db, serverID, groupID, ruleID, &existing)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	existing.Enabled = boolPtr(false)
	return db.Save(&existing).Error
}

func relayNodeIsOrphaned(item node.Node, groupID int64, currentRuleIDs map[string]struct{}) bool {
	if !relayNodeBelongsToGroup(item, groupID) {
		return false
	}
	_, current := currentRuleIDs[item.RelayRuleId]
	return !current
}

func validateRelaySubscriptionRequest(autoUpdate bool, rawURL string) error {
	if autoUpdate {
		return fmt.Errorf("auto_update is not supported")
	}
	parsed, err := url.ParseRequestURI(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("subscription url must use http or https")
	}
	return nil
}

func currentHealthResults(rules []types.NodeRelayRule, reported []types.RelaySubscriptionGroupHealthResult) (map[string]types.RelaySubscriptionGroupHealthResult, error) {
	current := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID != "" {
			current[rule.ID] = struct{}{}
		}
	}
	results := make(map[string]types.RelaySubscriptionGroupHealthResult, len(reported))
	for _, result := range reported {
		if _, ok := current[result.RuleID]; !ok {
			return nil, fmt.Errorf("relay rule %q is not current for this subscription group", result.RuleID)
		}
		results[result.RuleID] = result
	}
	return results, nil
}

func uniqueRelayNodeName(groupName string, used map[string]struct{}) string {
	base := strings.TrimSpace(groupName)
	if base == "" {
		base = "Relay Node"
	}
	if _, exists := used[base]; !exists {
		return base
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s %d", base, suffix)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
}

func sidecarRelayRules(rules []types.NodeRelayRule, groupID int64) []types.NodeRelayRule {
	result := make([]types.NodeRelayRule, 0, len(rules))
	for index, rule := range rules {
		mapped := rule
		mapped.ID = subscriptionRelayRuleID(groupID, rule.ID)
		protocol := strings.ToLower(strings.TrimSpace(rule.TargetProtocol))
		if protocol == "anytls" || protocol == "vless" || protocol == "trojan" || protocol == "shadowsocks" {
			mapped.TargetProtocol = "socks"
			mapped.TargetSecurity = "none"
			mapped.TargetAddress = "127.0.0.1"
			mapped.TargetPort = rule.SidecarPort
			if mapped.TargetPort == 0 {
				mapped.TargetPort = 31001 + int((groupID-1)*100) + index
			}
			mapped.TargetSNI = ""
			mapped.TargetTransport = "tcp"
			mapped.TargetHost = ""
			mapped.TargetPath = ""
			mapped.TargetXHTTPMode = ""
			mapped.TargetXHTTPExtra = ""
			mapped.TargetFlow = ""
			mapped.TargetFingerprint = ""
			mapped.TargetALPN = ""
			mapped.TargetUUID = ""
			mapped.TargetPassword = ""
			mapped.TargetMethod = ""
			mapped.TargetCipher = ""
			mapped.TargetPlugin = ""
			mapped.TargetPluginOpts = ""
			mapped.TargetAllowInsecure = false
		}
		result = append(result, mapped)
	}
	return result
}

const subscriptionRelayRulePrefix = "relay-subscription-group:"

func subscriptionRelayRuleID(groupID int64, ruleID string) string {
	return fmt.Sprintf("%s%d:%s", subscriptionRelayRulePrefix, groupID, ruleID)
}

func mergeSubscriptionRelayRules(existing []types.NodeRelayRule, groups map[int64][]types.NodeRelayRule) ([]types.NodeRelayRule, error) {
	legacyOwnedRules := make(map[types.NodeRelayRule]struct{})
	for groupID, rules := range groups {
		derived := sidecarRelayRules(rules, groupID)
		for index, candidate := range derived {
			if candidate.TargetProtocol != "socks" || candidate.TargetAddress != "127.0.0.1" || candidate.TargetPort <= 0 {
				continue
			}
			candidate.ID = rules[index].ID
			legacyOwnedRules[candidate] = struct{}{}
		}
	}
	manualRules := make([]types.NodeRelayRule, 0, len(existing))
	for _, rule := range existing {
		if strings.HasPrefix(rule.ID, subscriptionRelayRulePrefix) {
			continue
		}
		if _, legacyOwned := legacyOwnedRules[rule]; legacyOwned {
			continue
		}
		manualRules = append(manualRules, rule)
	}
	merged := append([]types.NodeRelayRule(nil), manualRules...)
	groupIDs := make([]int64, 0, len(groups))
	for groupID := range groups {
		groupIDs = append(groupIDs, groupID)
	}
	sort.Slice(groupIDs, func(i, j int) bool { return groupIDs[i] < groupIDs[j] })
	for _, groupID := range groupIDs {
		derived := sidecarRelayRules(groups[groupID], groupID)
		for _, candidate := range derived {
			for _, manual := range manualRules {
				if manual.ListenPort == candidate.ListenPort {
					return nil, fmt.Errorf("legacy migration conflict: manual relay rule %q and subscription rule %q both use listen_port %d", manual.ID, candidate.ID, candidate.ListenPort)
				}
			}
		}
		merged = append(merged, derived...)
	}
	return merged, nil
}

func relaySubscriptionRulesRevision(rules []types.NodeRelayRule) (string, error) {
	data, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func relayPreviewBinding(row node.RelaySubscriptionGroup, previewRules []types.NodeRelayRule) (relayPreviewTokenBinding, error) {
	var currentRules []types.NodeRelayRule
	if err := json.Unmarshal([]byte(row.Rules), &currentRules); err != nil {
		return relayPreviewTokenBinding{}, err
	}
	revision, err := relaySubscriptionRulesRevision(currentRules)
	if err != nil {
		return relayPreviewTokenBinding{}, err
	}
	rulesDigest, err := relaySubscriptionRulesRevision(previewRules)
	if err != nil {
		return relayPreviewTokenBinding{}, err
	}
	return relayPreviewTokenBinding{
		GroupID:         row.Id,
		URL:             row.URL,
		ListenPortStart: row.ListenPortStart,
		ListenPortStep:  row.ListenPortStep,
		Revision:        revision,
		RulesDigest:     rulesDigest,
	}, nil
}

func signRelayPreviewToken(secret string, binding relayPreviewTokenBinding, issuedAt time.Time) (string, error) {
	issued := strconv.FormatInt(issuedAt.Unix(), 10)
	mac, err := relayPreviewTokenMAC(secret, binding, issued)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(issued)) + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func verifyRelayPreviewToken(secret, token string, binding relayPreviewTokenBinding, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("invalid preview token")
	}
	issuedBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("invalid preview token")
	}
	issuedUnix, err := strconv.ParseInt(string(issuedBytes), 10, 64)
	if err != nil {
		return errors.New("invalid preview token")
	}
	issuedAt := time.Unix(issuedUnix, 0)
	if issuedAt.After(now.Add(time.Minute)) || now.Sub(issuedAt) > relayPreviewTokenTTL {
		return errors.New("preview token expired")
	}
	actualMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid preview token")
	}
	expectedMAC, err := relayPreviewTokenMAC(secret, binding, string(issuedBytes))
	if err != nil {
		return err
	}
	if !hmac.Equal(actualMAC, expectedMAC) {
		return errors.New("preview token does not match current subscription configuration")
	}
	return nil
}

func relayPreviewTokenMAC(secret string, binding relayPreviewTokenBinding, issued string) ([]byte, error) {
	payload, err := json.Marshal(struct {
		IssuedAt string `json:"issued_at"`
		relayPreviewTokenBinding
	}{IssuedAt: issued, relayPreviewTokenBinding: binding})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func withCurrentRelayRevision(rules []types.NodeRelayRule, reported string, mutate func() error) error {
	current, err := relaySubscriptionRulesRevision(rules)
	if err != nil {
		return err
	}
	if reported == "" || reported != current {
		return fmt.Errorf("%w: reported %q, current %q", errRelaySubscriptionRevisionMismatch, reported, current)
	}
	return mutate()
}

func shouldRecordRelayHealthFailure(err error) bool {
	return !errors.Is(err, errRelaySubscriptionRevisionMismatch)
}

func assignSidecarPorts(rules, oldRules []types.NodeRelayRule, occupied map[int]struct{}) ([]types.NodeRelayRule, error) {
	const poolStart, poolEnd = 31001, 61000
	if len(rules) > poolEnd-poolStart+1 {
		return nil, fmt.Errorf("subscription group supports at most %d relay rules", poolEnd-poolStart+1)
	}
	oldPorts := make(map[string]int, len(oldRules))
	for index, rule := range oldRules {
		port := rule.SidecarPort
		if port == 0 {
			port = poolStart + index
		}
		if rule.ID != "" && port >= poolStart && port <= poolEnd {
			oldPorts[rule.ID] = port
		}
	}
	assigned := append([]types.NodeRelayRule(nil), rules...)
	used := make(map[int]struct{}, len(assigned)+len(occupied))
	for port := range occupied {
		used[port] = struct{}{}
	}
	for index := range assigned {
		if port, ok := oldPorts[assigned[index].ID]; ok {
			if _, occupied := used[port]; !occupied {
				assigned[index].SidecarPort = port
				used[port] = struct{}{}
			} else {
				assigned[index].SidecarPort = 0
			}
		} else {
			assigned[index].SidecarPort = 0
		}
	}
	nextPort := poolStart
	for index := range assigned {
		if assigned[index].SidecarPort != 0 {
			continue
		}
		for nextPort <= poolEnd {
			if _, exists := used[nextPort]; !exists {
				break
			}
			nextPort++
		}
		if nextPort > poolEnd {
			return nil, fmt.Errorf("server sidecar port pool is exhausted")
		}
		assigned[index].SidecarPort = nextPort
		used[nextPort] = struct{}{}
		nextPort++
	}
	return assigned, nil
}

func validateSubscriptionRuntimeRules(rules []types.NodeRelayRule) error {
	if err := nodeconfig.ValidateRelayRules(rules); err != nil {
		return err
	}
	for _, rule := range nodeconfig.NormalizeRelayRules(rules) {
		if !rule.Enabled {
			continue
		}
		switch rule.TargetProtocol {
		case "anytls", "vless", "trojan", "shadowsocks":
		default:
			return fmt.Errorf("relay rule %q protocol %q is not supported by subscription runtime", rule.ID, rule.TargetProtocol)
		}
	}
	return nil
}

func relayGroupHealthStatus(rules []types.NodeRelayRule, results map[string]types.RelaySubscriptionGroupHealthResult) (string, string) {
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		result, ok := results[rule.ID]
		if !ok || !result.Healthy {
			if result.Error != "" {
				return "error", result.Error
			}
			return "error", fmt.Sprintf("relay rule %q is unhealthy", rule.ID)
		}
	}
	return "success", ""
}

func (l *RelaySubscriptionGroupLogic) serverSidecarPorts(db *gorm.DB, serverID, excludeGroupID int64) (map[int]struct{}, error) {
	var groups []node.RelaySubscriptionGroup
	if err := db.Where("server_id = ? AND id <> ?", serverID, excludeGroupID).Find(&groups).Error; err != nil {
		return nil, err
	}
	occupied := make(map[int]struct{})
	for _, group := range groups {
		var rules []types.NodeRelayRule
		if err := json.Unmarshal([]byte(group.Rules), &rules); err != nil {
			return nil, fmt.Errorf("parse relay subscription group %d rules: %w", group.Id, err)
		}
		for _, rule := range rules {
			if rule.SidecarPort >= 31001 && rule.SidecarPort <= 61000 {
				occupied[rule.SidecarPort] = struct{}{}
			}
		}
	}
	return occupied, nil
}

func relaySubscriptionGroupResponse(row node.RelaySubscriptionGroup) types.RelaySubscriptionGroup {
	var rules []types.NodeRelayRule
	if json.Unmarshal([]byte(row.Rules), &rules) != nil {
		rules = []types.NodeRelayRule{}
	}
	revision, _ := relaySubscriptionRulesRevision(rules)
	return types.RelaySubscriptionGroup{Id: row.Id, Revision: revision, ServerID: row.ServerId, Name: row.Name, URL: row.URL, Enabled: row.Enabled, AutoUpdate: row.AutoUpdate, UpdateInterval: row.UpdateInterval, ListenPortStart: row.ListenPortStart, ListenPortStep: row.ListenPortStep, Rules: rules, LastStatus: row.LastStatus, LastError: row.LastError, LastUpdatedAt: row.LastUpdatedAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}
