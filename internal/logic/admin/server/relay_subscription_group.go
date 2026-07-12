package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/perfect-panel/server/internal/logic/nodeconfig"
	"github.com/perfect-panel/server/internal/model/node"
	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
	"github.com/perfect-panel/server/pkg/logger"
	"github.com/perfect-panel/server/pkg/xerr"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

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
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(req.URL)), "http") {
		return xerr.NewErrCodeMsg(xerr.InvalidParams, "subscription url must use http or https")
	}
	db := l.svcCtx.Store.DB().WithContext(l.ctx)
	if req.Id == 0 {
		return db.Create(&node.RelaySubscriptionGroup{ServerId: req.ServerID, Name: req.Name, URL: req.URL, Enabled: req.Enabled, AutoUpdate: req.AutoUpdate, UpdateInterval: req.UpdateInterval, ListenPortStart: req.ListenPortStart, ListenPortStep: req.ListenPortStep, Rules: "[]", LastStatus: "never"}).Error
	}
	var row node.RelaySubscriptionGroup
	if err := db.Where("id = ? AND server_id = ?", req.Id, req.ServerID).First(&row).Error; err != nil {
		return err
	}
	row.Name, row.URL, row.Enabled, row.AutoUpdate = req.Name, req.URL, req.Enabled, req.AutoUpdate
	row.UpdateInterval, row.ListenPortStart, row.ListenPortStep = req.UpdateInterval, req.ListenPortStart, req.ListenPortStep
	return db.Save(&row).Error
}

func (l *RelaySubscriptionGroupLogic) Delete(id, serverID int64) error {
	return l.svcCtx.Store.DB().WithContext(l.ctx).Where("id = ? AND server_id = ?", id, serverID).Delete(&node.RelaySubscriptionGroup{}).Error
}

func (l *RelaySubscriptionGroupLogic) Preview(id, serverID int64) (*types.SubscriptionRelayPreviewResponse, error) {
	var row node.RelaySubscriptionGroup
	if err := l.svcCtx.Store.DB().WithContext(l.ctx).Where("id = ? AND server_id = ?", id, serverID).First(&row).Error; err != nil {
		return nil, err
	}
	return FetchSubscriptionRelayPreview(l.ctx, row.URL, SubscriptionRelayImportOptions{ListenPortStart: row.ListenPortStart, ListenPortStep: row.ListenPortStep})
}

func (l *RelaySubscriptionGroupLogic) Apply(req *types.RelaySubscriptionGroupApplyRequest, serverID int64) error {
	var row node.RelaySubscriptionGroup
	db := l.svcCtx.Store.DB().WithContext(l.ctx)
	if err := db.Where("id = ? AND server_id = ?", req.Id, serverID).First(&row).Error; err != nil {
		return err
	}
	if err := nodeconfig.ValidateRelayRules(req.Rules); err != nil {
		return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
	}
	nodeRules := sidecarRelayRules(req.Rules, row.Id)
	if err := nodeconfig.ValidateRelayRules(nodeRules); err != nil {
		return xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
	}
	rules, err := json.Marshal(req.Rules)
	if err != nil {
		return err
	}
	now := time.Now()
	row.Rules, row.LastStatus, row.LastError, row.LastUpdatedAt = string(rules), "success", "", &now
	if err := db.Save(&row).Error; err != nil {
		return err
	}
	return l.rebuildRelayRules(serverID)
}

func (l *RelaySubscriptionGroupLogic) SyncHealthyNodes(serverID int64, req *types.RelaySubscriptionGroupHealthRequest) error {
	var row node.RelaySubscriptionGroup
	db := l.svcCtx.Store.DB().WithContext(l.ctx)
	if err := db.Where("id = ? AND server_id = ?", req.GroupID, serverID).First(&row).Error; err != nil {
		return err
	}
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
	var rules []types.NodeRelayRule
	if err := json.Unmarshal([]byte(row.Rules), &rules); err != nil {
		return err
	}
	var allNodes []node.Node
	if err := db.Where("server_id = ?", serverID).Find(&allNodes).Error; err != nil {
		return err
	}
	results := make(map[string]types.RelaySubscriptionGroupHealthResult, len(req.Results))
	for _, result := range req.Results {
		results[result.RuleID] = result
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		usedNames := make(map[string]struct{}, len(allNodes))
		for _, item := range allNodes {
			if !relayNodeBelongsToGroup(item.Tags, req.GroupID) {
				usedNames[item.Name] = struct{}{}
			}
		}
		for _, rule := range rules {
			if rule.ID == "" {
				continue
			}
			result, reported := results[rule.ID]
			if !reported || !rule.Enabled || !result.Healthy {
				var existing node.Node
				if err := tx.Where("server_id = ? AND tags LIKE ?", serverID, "%relay-group:"+fmt.Sprint(req.GroupID)+"%relay-rule:"+rule.ID+"%").First(&existing).Error; err == nil {
					existing.Enabled = boolPtr(false)
					if err := tx.Save(&existing).Error; err != nil {
						return err
					}
				}
				continue
			}
			tags := "relay-group:" + fmt.Sprint(req.GroupID) + ",relay-rule:" + rule.ID
			var existing node.Node
			err := tx.Where("server_id = ? AND tags = ?", serverID, tags).First(&existing).Error
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
				existing = node.Node{Name: name, Tags: tags, Port: uint16(rule.ListenPort), Address: server.Address, ServerId: serverID, Protocol: protocol, Enabled: boolPtr(true)}
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
			existing.Name, existing.Port, existing.Address, existing.Protocol, existing.Enabled = name, uint16(rule.ListenPort), server.Address, protocol, boolPtr(true)
			if err := tx.Save(&existing).Error; err != nil {
				return err
			}
			usedNames[name] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return l.rebuildRelayRules(serverID)
}

func (l *RelaySubscriptionGroupLogic) rebuildRelayRules(serverID int64) error {
	db := l.svcCtx.Store.DB().WithContext(l.ctx)
	var groups []node.RelaySubscriptionGroup
	if err := db.Where("server_id = ? AND enabled = ?", serverID, true).Order("id asc").Find(&groups).Error; err != nil {
		return err
	}
	merged := make([]types.NodeRelayRule, 0)
	for _, group := range groups {
		var rules []types.NodeRelayRule
		if err := json.Unmarshal([]byte(group.Rules), &rules); err != nil {
			return err
		}
		merged = append(merged, sidecarRelayRules(rules, group.Id)...)
	}
	configResp, err := NewGetServerNodeConfigLogic(l.ctx, l.svcCtx).GetServerNodeConfig(&types.GetServerNodeConfigRequest{ServerID: serverID})
	if err != nil {
		return err
	}
	override := configResp.Override
	override.InheritRelayRules = false
	override.RelayRules = merged
	return NewUpdateServerNodeConfigLogic(l.ctx, l.svcCtx).UpdateServerNodeConfig(&types.UpdateServerNodeConfigRequest{ServerID: serverID, ServerNodeConfigOverride: override})
}

func boolPtr(value bool) *bool { return &value }

func relayNodeBelongsToGroup(tags string, groupID int64) bool {
	needle := "relay-group:" + fmt.Sprint(groupID)
	for _, tag := range strings.Split(tags, ",") {
		if strings.TrimSpace(tag) == needle {
			return true
		}
	}
	return false
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
	basePort := 31001 + int((groupID-1)*100)
	for index, rule := range rules {
		mapped := rule
		protocol := strings.ToLower(strings.TrimSpace(rule.TargetProtocol))
		if protocol == "anytls" || protocol == "vless" || protocol == "trojan" || protocol == "shadowsocks" {
			mapped.TargetProtocol = "socks"
			mapped.TargetSecurity = "none"
			mapped.TargetAddress = "127.0.0.1"
			mapped.TargetPort = basePort + index
			mapped.TargetSNI = ""
			mapped.TargetTransport = "tcp"
			mapped.TargetHost = ""
			mapped.TargetPath = ""
			mapped.TargetXHTTPMode = ""
			mapped.TargetXHTTPExtra = ""
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

func relaySubscriptionGroupResponse(row node.RelaySubscriptionGroup) types.RelaySubscriptionGroup {
	var rules []types.NodeRelayRule
	if json.Unmarshal([]byte(row.Rules), &rules) != nil {
		rules = []types.NodeRelayRule{}
	}
	return types.RelaySubscriptionGroup{Id: row.Id, ServerID: row.ServerId, Name: row.Name, URL: row.URL, Enabled: row.Enabled, AutoUpdate: row.AutoUpdate, UpdateInterval: row.UpdateInterval, ListenPortStart: row.ListenPortStart, ListenPortStep: row.ListenPortStep, Rules: rules, LastStatus: row.LastStatus, LastError: row.LastError, LastUpdatedAt: row.LastUpdatedAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}
