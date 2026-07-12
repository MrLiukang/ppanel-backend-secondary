package server

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	adminserver "github.com/perfect-panel/server/internal/logic/admin/server"
	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
)

func ReportRelaySubscriptionGroupHealthHandler(svcCtx *svc.ServiceContext) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if c.Query("secret_key") != svcCtx.Config.Node.NodeSecret {
			c.String(consts.StatusUnauthorized, "Unauthorized")
			return
		}
		serverID, err := strconv.ParseInt(c.Param("server_id"), 10, 64)
		if err != nil {
			c.String(consts.StatusBadRequest, "Invalid Params")
			return
		}
		var req types.RelaySubscriptionGroupHealthRequest
		if err := json.Unmarshal(c.Request.Body(), &req); err != nil {
			c.String(consts.StatusBadRequest, "Invalid JSON")
			return
		}
		if err := adminserver.NewRelaySubscriptionGroupLogic(ctx, svcCtx).SyncHealthyNodes(serverID, &req); err != nil {
			c.String(consts.StatusInternalServerError, err.Error())
			return
		}
		c.SetStatusCode(consts.StatusNoContent)
	}
}
