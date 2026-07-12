package system

import (
	"context"

	"github.com/perfect-panel/server/initialize"
	"github.com/perfect-panel/server/internal/config"
	"github.com/perfect-panel/server/internal/logic/nodeconfig"
	"github.com/perfect-panel/server/pkg/logger"
	"github.com/perfect-panel/server/pkg/xerr"
	"github.com/pkg/errors"

	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
)

type UpdateNodeConfigLogic struct {
	logger.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewUpdateNodeConfigLogic(ctx context.Context, svcCtx *svc.ServiceContext) *UpdateNodeConfigLogic {
	return &UpdateNodeConfigLogic{
		Logger: logger.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *UpdateNodeConfigLogic) UpdateNodeConfig(req *types.NodeConfig) error {
	if err := nodeconfig.ValidateRoutingRules(req.RoutingRules, req.Outbound); err != nil {
		return errors.Wrapf(xerr.NewErrCodeMsg(xerr.InvalidParams, "routing rules are invalid"), "routing rules are invalid: %v", err)
	}
	if err := nodeconfig.ValidateRelayRules(req.RelayRules); err != nil {
		return errors.Wrapf(xerr.NewErrCodeMsg(xerr.InvalidParams, "relay rules are invalid"), "relay rules are invalid: %v", err)
	}
	err := updateConfigFields(l.ctx, l.svcCtx, "server", convertedConfigFields(*req), config.NodeConfigKey)
	if err != nil {
		l.Errorw("[UpdateNodeConfig] update node config error", logger.Field("error", err.Error()))
		return errors.Wrapf(xerr.NewErrCode(xerr.DatabaseUpdateError), "update server config error: %v", err)
	}
	initialize.Node(l.svcCtx)
	return nil
}
