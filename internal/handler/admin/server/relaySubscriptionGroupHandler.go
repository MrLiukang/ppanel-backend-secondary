package server

import (
	"github.com/perfect-panel/server/internal/logic/admin/server"
	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
	"github.com/perfect-panel/server/pkg/hertzx"
	"github.com/perfect-panel/server/pkg/result"
)

func QueryRelaySubscriptionGroupsHandler(svcCtx *svc.ServiceContext) func(*hertzx.Context) {
	return func(c *hertzx.Context) {
		var req types.GetServerNodeConfigRequest
		_ = c.ShouldBind(&req)
		resp, err := server.NewRelaySubscriptionGroupLogic(c.Request.Context(), svcCtx).List(req.ServerID)
		result.HttpResult(c, resp, err)
	}
}

func SaveRelaySubscriptionGroupHandler(svcCtx *svc.ServiceContext) func(*hertzx.Context) {
	return func(c *hertzx.Context) {
		var req types.RelaySubscriptionGroupRequest
		_ = c.ShouldBind(&req)
		if err := svcCtx.Validate(&req); err != nil {
			result.ParamErrorResult(c, err)
			return
		}
		err := server.NewRelaySubscriptionGroupLogic(c.Request.Context(), svcCtx).Save(&req)
		result.HttpResult(c, nil, err)
	}
}

func DeleteRelaySubscriptionGroupHandler(svcCtx *svc.ServiceContext) func(*hertzx.Context) {
	return func(c *hertzx.Context) {
		var req types.RelaySubscriptionGroupRequest
		_ = c.ShouldBind(&req)
		err := server.NewRelaySubscriptionGroupLogic(c.Request.Context(), svcCtx).Delete(req.Id, req.ServerID)
		result.HttpResult(c, nil, err)
	}
}

func PreviewRelaySubscriptionGroupHandler(svcCtx *svc.ServiceContext) func(*hertzx.Context) {
	return func(c *hertzx.Context) {
		var req types.RelaySubscriptionGroupRequest
		_ = c.ShouldBind(&req)
		resp, err := server.NewRelaySubscriptionGroupLogic(c.Request.Context(), svcCtx).Preview(req.Id, req.ServerID)
		result.HttpResult(c, resp, err)
	}
}

func ApplyRelaySubscriptionGroupHandler(svcCtx *svc.ServiceContext) func(*hertzx.Context) {
	return func(c *hertzx.Context) {
		var req types.RelaySubscriptionGroupApplyRequest
		_ = c.ShouldBind(&req)
		if err := svcCtx.Validate(&req); err != nil {
			result.ParamErrorResult(c, err)
			return
		}
		err := server.NewRelaySubscriptionGroupLogic(c.Request.Context(), svcCtx).Apply(&req, req.ServerID)
		result.HttpResult(c, nil, err)
	}
}
