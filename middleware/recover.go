package middleware

import (
	"fmt"
	"github.com/gin-gonic/gin"                      // 引入Gin框架
	"github.com/songquanpeng/one-api/common"        // 引入项目中的公共模块
	"github.com/songquanpeng/one-api/common/logger" // 引入项目中的日志模块
	"net/http"                                      // 引入HTTP相关的标准库
	"runtime/debug"                                 // 引入用于获取堆栈信息的标准库
)

// RelayPanicRecover 是一个中间件函数，用于捕获并处理请求过程中发生的panic。
func RelayPanicRecover() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 使用defer和匿名函数来捕获panic
		defer func() {
			if err := recover(); err != nil {
				// 获取请求上下文
				ctx := c.Request.Context()
				// 打印错误信息到日志
				logger.Errorf(ctx, fmt.Sprintf("panic detected: %v", err))
				// 打印堆栈信息到日志
				logger.Errorf(ctx, fmt.Sprintf("stacktrace from panic: %s", string(debug.Stack())))
				// 打印请求方法和路径到日志
				logger.Errorf(ctx, fmt.Sprintf("request: %s %s", c.Request.Method, c.Request.URL.Path))
				// 获取并打印请求体到日志
				body, _ := common.GetRequestBody(c)
				logger.Errorf(ctx, fmt.Sprintf("request body: %s", string(body)))
				// 返回500状态码和错误信息给客户端
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": gin.H{
						"message": fmt.Sprintf("Panic detected, error: %v. Please submit an issue with the related log here: https://github.com/songquanpeng/one-api", err),
						"type":    "one_api_panic",
					},
				})
				// 中止请求处理链
				c.Abort()
			}
		}()
		// 继续处理请求
		c.Next()
	}
}
