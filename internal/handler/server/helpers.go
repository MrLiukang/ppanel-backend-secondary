package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
	"github.com/perfect-panel/server/pkg/result"
)

func ServerMiddleware(svcCtx *svc.ServiceContext) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		serverID, err := requestServerID(ctx)
		if err == nil && validServerToken(requestServerToken(ctx), svcCtx.Config.Node.NodeSecret, serverID, svcCtx.Config.Node.AllowLegacyNodeSecret) {
			ctx.Next(c)
			return
		}
		ctx.String(consts.StatusForbidden, "Forbidden")
		ctx.Abort()
	}
}

func deriveServerToken(secret string, serverID int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(serverID, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func validServerToken(token, secret string, serverID int64, allowLegacy bool) bool {
	if token == "" || secret == "" || serverID <= 0 {
		return false
	}
	if hmac.Equal([]byte(token), []byte(deriveServerToken(secret, serverID))) {
		return true
	}
	return allowLegacy && hmac.Equal([]byte(token), []byte(secret))
}

func requestServerID(ctx *app.RequestContext) (int64, error) {
	raw := ctx.Param("server_id")
	if raw == "" {
		raw = ctx.Query("server_id")
	}
	return strconv.ParseInt(raw, 10, 64)
}

func requestServerToken(ctx *app.RequestContext) string {
	if authorization := string(ctx.Request.Header.Peek("Authorization")); strings.HasPrefix(authorization, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	}
	if token := string(ctx.Request.Header.Peek("X-PPANEL-Server-Token")); token != "" {
		return token
	}
	return ctx.Query("secret_key")
}

func authorizeServerRequest(ctx *app.RequestContext, svcCtx *svc.ServiceContext, serverID int64) bool {
	return validServerToken(requestServerToken(ctx), svcCtx.Config.Node.NodeSecret, serverID, svcCtx.Config.Node.AllowLegacyNodeSecret)
}

func serverCommonRequest(ctx *app.RequestContext) (types.ServerCommon, error) {
	var serverID int64
	if rawServerID := ctx.Query("server_id"); rawServerID != "" {
		id, err := strconv.ParseInt(rawServerID, 10, 64)
		if err != nil {
			return types.ServerCommon{}, err
		}
		serverID = id
	}
	return types.ServerCommon{
		Protocol:  ctx.Query("protocol"),
		ServerId:  serverID,
		SecretKey: ctx.Query("secret_key"),
	}, nil
}

func queryValues(ctx *app.RequestContext, keys ...string) []string {
	var values []string
	for _, key := range keys {
		for _, value := range ctx.QueryArgs().PeekAll(key) {
			values = append(values, string(value))
		}
	}
	return values
}

func writeHeaders(ctx *app.RequestContext, headers map[string]string) {
	for key, value := range headers {
		ctx.Header(key, value)
	}
}

func writeHTTPResult(ctx *app.RequestContext, resp interface{}, err error) {
	res := result.BuildHTTPResult(resp, err)
	ctx.JSON(res.StatusCode, res.Body)
}

func writeParamError(ctx *app.RequestContext, err error) {
	resp := result.BuildParamErrorResult(err)
	ctx.JSON(resp.StatusCode, resp.Body)
}
