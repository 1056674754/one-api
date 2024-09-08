package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/songquanpeng/one-api/common"
	"github.com/songquanpeng/one-api/common/config"
	"github.com/songquanpeng/one-api/common/ctxkey"
	"github.com/songquanpeng/one-api/common/random"
	"github.com/songquanpeng/one-api/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	//TenantId int    `json:"tenantId"`
}

func Login(c *gin.Context) {
	if !config.PasswordLoginEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员关闭了密码登录",
			"success": false,
		})
		return
	}
	var loginRequest LoginRequest
	err := json.NewDecoder(c.Request.Body).Decode(&loginRequest)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "无效的参数",
			"success": false,
		})
		return
	}
	username := loginRequest.Username
	password := loginRequest.Password
	//tenantId := loginRequest.TenantId

	if username == "" || password == "" {
		c.JSON(http.StatusOK, gin.H{
			"message": "无效的账号密码",
			"success": false,
		})
		return
	}

	user := model.User{
		Username: username,
		Password: password,
		//TenantId: tenantId,
	}
	err = user.ValidateAndFill()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	SetupLogin(&user, c)
}

type TenantLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TenantId int    `json:"tenantId"`
}

func TenantUserLogin(c *gin.Context) {
	if !config.PasswordLoginEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员关闭了密码登录",
			"success": false,
		})
		return
	}
	var loginRequest TenantLoginRequest
	err := json.NewDecoder(c.Request.Body).Decode(&loginRequest)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "无效的参数",
			"success": false,
		})
		return
	}
	username := loginRequest.Username
	password := loginRequest.Password
	tenantId := loginRequest.TenantId

	if username == "" || password == "" {
		c.JSON(http.StatusOK, gin.H{
			"message": "无效的账号密码",
			"success": false,
		})
		return
	}

	user := model.User{
		Username: username,
		Password: password,
		TenantId: tenantId,
	}
	err = user.ValidateAndFill()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	SetupLogin(&user, c)
}

type TenantGetRequest struct {
	Domain     *string `json:"domain,omitempty"`
	TenantName *string `json:"tenantName,omitempty"`
}

func TenantGet(c *gin.Context) {
	//if !config.PasswordLoginEnabled {
	//	c.JSON(http.StatusOK, gin.H{
	//		"message": "管理员关闭了密码登录",
	//		"success": false,
	//	})
	//	return
	//}

	//var tenantGetRequest TenantGetRequest
	//err := json.NewDecoder(c.Request.Body).Decode(&tenantGetRequest)
	//if err != nil {
	//	c.JSON(http.StatusOK, gin.H{
	//		"message": "无效的参数",
	//		"success": false,
	//	})
	//	return
	//}

	//domain := *tenantGetRequest.Domain
	//tenantName := *tenantGetRequest.TenantName
	//password := tenantGetRequest.Password
	//tenantId := tenantGetRequest.TenantId

	//if domain != "" && tenantName != "" {
	//	c.JSON(http.StatusOK, gin.H{
	//		"message": "无效的参数",
	//		"success": false,
	//	})
	//	return
	//}
	//
	//user := model.User{
	//	Username: username,
	//	Password: password,
	//	TenantId: tenantId,
	//}
	//err = user.ValidateAndFill()
	//if err != nil {
	//	c.JSON(http.StatusOK, gin.H{
	//		"message": err.Error(),
	//		"success": false,
	//	})
	//	return
	//}

	var request TenantGetRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.User
	query := model.DB.Model(&model.User{}).Where("is_on_prom = ?", false)

	if request.Domain != nil {
		query = query.Where("tenant_domain = ?", *request.Domain).Where("id = tenant_id")
	}

	if request.TenantName != nil {
		query = query.Where("username = ?", *request.TenantName).Where("id = tenant_id")
	}

	if err := query.First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "tenant not found"})
		} else {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		}
		return
	}

	// Return only the necessary fields
	cleanUser := map[string]interface{}{
		"id":            user.Id,
		"tenant_id":     user.TenantId,
		"tenant_domain": user.TenantDomain,
		"display_name":  user.DisplayName,
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": cleanUser})

}

// setup session & cookies and then return user info
func SetupLogin(user *model.User, c *gin.Context) {
	session := sessions.Default(c)
	session.Set("id", user.Id)
	session.Set("username", user.Username)
	session.Set("role", user.Role)
	session.Set("status", user.Status)
	err := session.Save()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "无法保存会话信息，请重试",
			"success": false,
		})
		return
	}
	cleanUser := model.User{
		Id:          user.Id,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		Status:      user.Status,
		TenantId:    user.TenantId,
		IsOnProm:    user.IsOnProm,
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "",
		"success": true,
		"data":    cleanUser,
	})
}

func Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	err := session.Save()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "",
		"success": true,
	})
}

func Register(c *gin.Context) {
	if !config.RegisterEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员关闭了新用户注册",
			"success": false,
		})
		return
	}
	if !config.PasswordRegisterEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员关闭了通过密码进行注册，请使用第三方账户验证的形式进行注册",
			"success": false,
		})
		return
	}
	var user model.User
	err := json.NewDecoder(c.Request.Body).Decode(&user)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}
	if err := common.Validate.Struct(&user); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "输入不合法 " + err.Error(),
		})
		return
	}
	if config.EmailVerificationEnabled {
		if user.Email == "" || user.VerificationCode == "" {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员开启了邮箱验证，请输入邮箱地址和验证码",
			})
			return
		}
		if !common.VerifyCodeWithKey(user.Email, user.VerificationCode, common.EmailVerificationPurpose) {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "验证码错误或已过期",
			})
			return
		}
	}
	affCode := user.AffCode // this code is the inviter's code, not the user's own code
	inviterId, _ := model.GetUserIdByAffCode(affCode)
	cleanUser := model.User{
		Username:    user.Username,
		Password:    user.Password,
		DisplayName: user.Username,
		InviterId:   inviterId,
	}
	if config.EmailVerificationEnabled {
		cleanUser.Email = user.Email
	}
	if err := cleanUser.Insert(inviterId); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func GetAllUsers(c *gin.Context) {
	loginUser, exists := c.Get("loginUser")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "此接口必须登录"})
		return
	}
	// 将 loginUser 转换为你需要的类型
	loginUserObj := loginUser.(*model.User)

	p, _ := strconv.Atoi(c.Query("p"))
	if p < 1 {
		p = 1
	}

	pageSizeStr := c.Query("pageSize")
	pageSize, psErr := strconv.Atoi(pageSizeStr)
	if psErr != nil {
		log.Printf("Invalid pageSize: %s, using default 10", pageSizeStr)
		pageSize = 10
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	order := c.DefaultQuery("order", "")

	users, total, totalPage, err := model.GetAllUsers(loginUserObj, (p-1)*pageSize, pageSize, order, loginUserObj.IsOnProm == 1)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "",
		"data":      users,
		"total":     total,
		"totalPage": totalPage,
		"pageSize":  pageSize,
		"page":      p,
	})
}

func SearchUsers(c *gin.Context) {
	keyword := c.Query("keyword")
	users, err := model.SearchUsers(keyword)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    users,
	})
	return
}

func GetUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user, err := model.GetUserById(id, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	myRole := c.GetInt(ctxkey.Role)
	if myRole <= user.Role && myRole != model.RoleSystemRootUser {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权获取同级或更高等级用户的信息",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    user,
	})
	return
}

func GetUserDashboard(c *gin.Context) {
	id := c.GetInt(ctxkey.Id)
	now := time.Now()
	startOfDay := now.Truncate(24*time.Hour).AddDate(0, 0, -6).Unix()
	endOfDay := now.Truncate(24 * time.Hour).Add(24*time.Hour - time.Second).Unix()

	dashboards, err := model.SearchLogsByDayAndModel(id, int(startOfDay), int(endOfDay))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无法获取统计信息",
			"data":    nil,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    dashboards,
	})
	return
}

func GenerateAccessToken(c *gin.Context) {
	id := c.GetInt(ctxkey.Id)
	user, err := model.GetUserById(id, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user.AccessToken = random.GetUUID()

	if model.DB.Where("access_token = ?", user.AccessToken).First(user).RowsAffected != 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "请重试，系统生成的 UUID 竟然重复了！",
		})
		return
	}

	if err := user.Update(false); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    user.AccessToken,
	})
	return
}

func GetAffCode(c *gin.Context) {
	id := c.GetInt(ctxkey.Id)
	user, err := model.GetUserById(id, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	if user.AffCode == "" {
		user.AffCode = random.GetRandomString(4)
		if err := user.Update(false); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    user.AffCode,
	})
	return
}

func GetSelf(c *gin.Context) {
	id := c.GetInt(ctxkey.Id)
	user, err := model.GetUserById(id, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    user,
	})
	return
}

func UpdateUser(c *gin.Context) {
	var updatedUser model.User
	err := json.NewDecoder(c.Request.Body).Decode(&updatedUser)
	if err != nil || updatedUser.Id == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}
	if updatedUser.Password == "" {
		updatedUser.Password = "$I_LOVE_U" // make Validator happy :)
	}
	if err := common.Validate.Struct(&updatedUser); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "输入不合法 " + err.Error(),
		})
		return
	}
	originUser, err := model.GetUserById(updatedUser.Id, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	myRole := c.GetInt(ctxkey.Role)
	if myRole <= originUser.Role && myRole != model.RoleSystemRootUser {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权更新同权限等级或更高权限等级的用户信息",
		})
		return
	}
	if myRole <= updatedUser.Role && myRole != model.RoleSystemRootUser {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权将其他用户权限等级提升到大于等于自己的权限等级",
		})
		return
	}
	if updatedUser.Password == "$I_LOVE_U" {
		updatedUser.Password = "" // rollback to what it should be
	}
	updatePassword := updatedUser.Password != ""
	if err := updatedUser.Update(updatePassword); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	if originUser.Quota != updatedUser.Quota {
		model.RecordLog(originUser.Id, model.LogTypeManage, fmt.Sprintf("管理员将用户额度从 %s修改为 %s", common.LogQuota(originUser.Quota), common.LogQuota(updatedUser.Quota)))
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func UpdateTenantUser(c *gin.Context) {
	var updatedUser model.User
	err := json.NewDecoder(c.Request.Body).Decode(&updatedUser)
	if err != nil || updatedUser.Id == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}
	if updatedUser.Password == "" {
		updatedUser.Password = "$I_LOVE_U" // make Validator happy :)
	}
	if err := common.Validate.Struct(&updatedUser); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "输入不合法 " + err.Error(),
		})
		return
	}
	originUser, err := model.GetUserById(updatedUser.Id, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	myRole := c.GetInt(ctxkey.Role)
	if myRole <= originUser.Role && myRole != model.RoleSystemRootUser {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权更新同权限等级或更高权限等级的用户信息",
		})
		return
	}
	if myRole <= updatedUser.Role && myRole != model.RoleSystemRootUser {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权将其他用户权限等级提升到大于等于自己的权限等级",
		})
		return
	}
	if updatedUser.Password == "$I_LOVE_U" {
		updatedUser.Password = "" // rollback to what it should be
	}
	updatePassword := updatedUser.Password != ""
	if err := updatedUser.Update(updatePassword); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	//if originUser.Quota != updatedUser.Quota {
	//	model.RecordLog(originUser.Id, model.LogTypeManage, fmt.Sprintf("管理员将用户额度从 %s修改为 %s", common.LogQuota(originUser.Quota), common.LogQuota(updatedUser.Quota)))
	//}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func UpdateSelf(c *gin.Context) {
	var user model.User
	err := json.NewDecoder(c.Request.Body).Decode(&user)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}
	if user.Password == "" {
		user.Password = "$I_LOVE_U" // make Validator happy :)
	}
	if err := common.Validate.Struct(&user); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "输入不合法 " + err.Error(),
		})
		return
	}

	cleanUser := model.User{
		Id:          c.GetInt(ctxkey.Id),
		Username:    user.Username,
		Password:    user.Password,
		DisplayName: user.DisplayName,
	}
	if user.Password == "$I_LOVE_U" {
		user.Password = "" // rollback to what it should be
		cleanUser.Password = ""
	}
	updatePassword := user.Password != ""
	if err := cleanUser.Update(updatePassword); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func DeleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	originUser, err := model.GetUserById(id, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	myRole := c.GetInt("role")
	if myRole <= originUser.Role {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权删除同权限等级或更高权限等级的用户",
		})
		return
	}
	err = model.DeleteUserById(id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "",
		})
		return
	}
}

func DeleteSelf(c *gin.Context) {
	id := c.GetInt("id")
	user, _ := model.GetUserById(id, false)

	if user.Role == model.RoleSystemRootUser {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "不能删除超级管理员账户",
		})
		return
	}

	err := model.DeleteUserById(id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func CreateUser(c *gin.Context) {
	loginUser, exists := c.Get("loginUser")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "此接口必须登录"})
		return
	}

	// 将 loginUser 转换为你需要的类型
	loginUserObj := loginUser.(*model.User)

	var user model.User
	err := json.NewDecoder(c.Request.Body).Decode(&user)
	if err != nil || user.Username == "" || user.Password == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}
	if err := common.Validate.Struct(&user); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "输入不合法 " + err.Error(),
		})
		return
	}

	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	myRole := c.GetInt("role")
	if user.Role >= myRole {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无法创建权限大于等于自己的用户",
		})
		return
	}

	cleanUser := model.User{
		Username:    user.Username,
		Password:    user.Password,
		DisplayName: user.DisplayName,
		TenantId:    -1,
		Role:        model.RoleTenantUser,
	}

	if loginUserObj.Role == model.RoleSystemRootUser || loginUserObj.Role == model.RoleSystemAdminUser {
		// Even for admin users, we cannot fully trust them!
		// TODO 区分加的是RoleSystemAdminUser还是租户管理员, 暂时不能添加局端用户
		cleanUser.Role = model.RoleTenantSuperAdmin
		cleanUser.IsOU = 1
	} else {
		cleanUser.TenantId = loginUserObj.TenantId
	}

	if err := cleanUser.Insert(0); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func CreateTenantUser(c *gin.Context) {
	loginUser, exists := c.Get("loginUser")

	if !exists {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "此接口必须登录"})
		return
	}

	// 将 loginUser 转换为你需要的类型
	loginUserObj := loginUser.(*model.User)

	var user model.User
	err := json.NewDecoder(c.Request.Body).Decode(&user)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}

	if user.Username == "" || user.Password == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "请检查账号密码",
		})
		return
	}

	if err := common.Validate.Struct(&user); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "输入不合法 " + err.Error(),
		})
		return
	}

	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	myRole := c.GetInt("role")
	if user.Role >= myRole {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无法创建权限大于等于自己的用户",
		})
		return
	}

	cleanUser := model.User{
		Username:    user.Username,
		Password:    user.Password,
		DisplayName: user.DisplayName,
		ParentsId:   user.ParentsId,
		TenantId:    loginUserObj.TenantId,
		Role:        model.RoleTenantUser,
	}

	if err := cleanUser.Insert(0); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "此账户已注册",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func CreateDept(c *gin.Context) {
	loginUser, exists := c.Get("loginUser")

	if !exists {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "此接口必须登录"})
		return
	}

	// 将 loginUser 转换为你需要的类型
	loginUserObj := loginUser.(*model.User)

	fmt.Print("TenantId: ", loginUserObj.TenantId, "\n")
	if loginUserObj.Role < model.RoleTenantAdmin {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "您无权创建子部门",
		})
		return
	}

	var dept model.User
	err := json.NewDecoder(c.Request.Body).Decode(&dept)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}

	if dept.DisplayName == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "请检查, 必须输入部门显示名称",
		})
		return
	}

	if err := common.Validate.Struct(&dept); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "输入不合法 " + err.Error(),
		})
		return
	}

	if dept.Username == "" {
		dept.Username = "T_" + strconv.Itoa(loginUserObj.TenantId) + "_" + dept.DisplayName
	}
	//myRole := c.GetInt("role")
	//if user.Role >= myRole {
	//	c.JSON(http.StatusOK, gin.H{
	//		"success": false,
	//		"message": "无法创建权限大于等于自己的用户",
	//	})
	//	return
	//}

	cleanUser := model.User{
		Username:    dept.Username,
		Password:    dept.Password,
		DisplayName: dept.DisplayName,
		ParentsId:   dept.ParentsId,
		TenantId:    loginUserObj.TenantId,
		IsOU:        1,
		Role:        model.RoleTenantAdmin,
	}

	if err := cleanUser.Insert(0); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "此部门账号已注册, 请修改",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

type ManageRequest struct {
	Username string `json:"username"`
	Action   string `json:"action"`
}

// ManageUser Only admin user can do this
func ManageUser(c *gin.Context) {
	var req ManageRequest
	err := json.NewDecoder(c.Request.Body).Decode(&req)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}
	user := model.User{
		Username: req.Username,
	}
	// Fill attributes
	model.DB.Where(&user).First(&user)
	if user.Id == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}
	myRole := c.GetInt("role")
	if myRole <= user.Role && myRole != model.RoleSystemRootUser {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权更新同权限等级或更高权限等级的用户信息",
		})
		return
	}
	switch req.Action {
	case "disable":
		user.Status = model.UserStatusDisabled
		if user.Role == model.RoleSystemRootUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法禁用超级管理员用户",
			})
			return
		}
	case "enable":
		user.Status = model.UserStatusEnabled
	case "delete":
		if user.Role == model.RoleSystemRootUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法删除超级管理员用户",
			})
			return
		}
		if err := user.Delete(); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	case "promote":
		if myRole != model.RoleSystemRootUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "普通管理员用户无法提升其他用户为管理员",
			})
			return
		}
		if user.Role >= model.RoleSystemAdminUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "该用户已经是管理员",
			})
			return
		}
		user.Role = model.RoleSystemAdminUser
	case "demote":
		if user.Role == model.RoleSystemRootUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法降级超级管理员用户",
			})
			return
		}
		if user.Role == model.RoleTenantUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "该用户已经是普通用户",
			})
			return
		}
		user.Role = model.RoleTenantUser
	}

	if err := user.Update(false); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	clearUser := model.User{
		Role:   user.Role,
		Status: user.Status,
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    clearUser,
	})
	return
}

type ManageTenantUserRequest struct {
	Id     int    `json:"id"`
	Action string `json:"action"`
}

func ManageTenantUser(c *gin.Context) {
	var req ManageTenantUserRequest
	err := json.NewDecoder(c.Request.Body).Decode(&req)

	myRole := c.GetInt("role")
	myTenantId := c.GetInt("tenantId")

	fmt.Println("myRole", myRole, "myTenantId", myTenantId)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的参数",
		})
		return
	}
	user := model.User{
		Id:       req.Id,
		TenantId: myTenantId,
	}
	// 打印查询条件
	fmt.Printf("Querying user with Id: %d and TenantId: %d\n", user.Id, user.TenantId)

	// 执行查询
	result := model.DB.Where(&user).First(&user)

	// 检查查询结果
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Printf("User not found: Id=%d, TenantId=%d\n", user.Id, user.TenantId)
		} else {
			log.Printf("Error querying user: %v\n", result.Error)
		}
	} else {
		// 打印查询结果
		fmt.Printf("User found: %+v\n", user)
	}

	if user.Id == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "租户用户不存在",
		})
		return
	}
	fmt.Println("myRole", myRole, "user.Role", user.Role, "myRole <= user.Role", myRole <= user.Role, "myTenantId", myTenantId)

	if myRole <= user.Role && myRole <= model.RoleTenantSuperAdmin {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无权更新同权限等级或更高权限等级的用户信息",
		})
		return
	}
	switch req.Action {
	case "disable":
		user.Status = model.UserStatusDisabled
		if user.Role == model.RoleSystemRootUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法禁用超级管理员用户",
			})
			return
		}
	case "enable":
		user.Status = model.UserStatusEnabled
	case "delete":
		if user.Role == model.RoleSystemRootUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法删除超级管理员用户",
			})
			return
		}

		if user.Quota > 30000 {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "Account have too much quota, Please remove them before delete!!!",
			})
			return
		}

		if user.IsOU != 0 {
			deptDTO, _ := model.GetDeptWithChildren(&user)
			if len(deptDTO.Children) > 0 {
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": "Please delete children first!!!",
				})
				return

			}

		}
		if err := user.Delete(); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	case "promote":
		if myRole < model.RoleTenantSuperAdmin {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "普通管理员用户无法提升其他用户",
			})
			return
		}
		if user.Role >= model.RoleTenantAdmin {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "该用户已经是管理员",
			})
			return
		}

		//else if user.Role == model.RoleTenantAdmin {
		//	user.Role = model.RoleTenantSuperAdmin
		//}
		if user.Role == model.RoleTenantUser {
			user.Role = model.RoleTenantAdmin
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法继续提升租户用户权限",
			})
			return
		}
	case "demote":
		if myRole < model.RoleTenantSuperAdmin {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "普通管理员用户无法降低其他用户",
			})
			return
		}
		if user.Role >= model.RoleTenantSuperAdmin {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法降级租户管理员及以上用户",
			})
			return
		}
		if user.Role == model.RoleTenantUser {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "该用户已经是普通用户",
			})
			return
		}

		if user.Role == model.RoleTenantSuperAdmin {
			user.Role = model.RoleTenantAdmin

		} else if user.Role == model.RoleTenantAdmin {
			user.Role = model.RoleTenantUser
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "无法继续降低租户用户权限",
			})
			return
		}
	}

	if err := user.Update(false); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	clearUser := model.User{
		Role:   user.Role,
		Status: user.Status,
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    clearUser,
	})
	return
}

func EmailBind(c *gin.Context) {
	email := c.Query("email")
	code := c.Query("code")
	if !common.VerifyCodeWithKey(email, code, common.EmailVerificationPurpose) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "验证码错误或已过期",
		})
		return
	}
	id := c.GetInt("id")
	user := model.User{
		Id: id,
	}
	err := user.FillUserById()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user.Email = email
	// no need to check if this email already taken, because we have used verification code to check it
	err = user.Update(false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	if user.Role == model.RoleSystemRootUser {
		config.RootUserEmail = email
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

type topUpRequest struct {
	Key string `json:"key"`
}

func TopUp(c *gin.Context) {
	req := topUpRequest{}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	id := c.GetInt("id")
	quota, err := model.Redeem(req.Key, id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    quota,
	})
	return
}

type adminTopUpRequest struct {
	UserId int    `json:"user_id"`
	Quota  int    `json:"quota"`
	Remark string `json:"remark"`
}

func AdminTopUp(c *gin.Context) {
	req := adminTopUpRequest{}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	err = model.IncreaseUserQuota(req.UserId, int64(req.Quota))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	if req.Remark == "" {
		req.Remark = fmt.Sprintf("通过 API 充值 %s", common.LogQuota(int64(req.Quota)))
	}
	model.RecordTopupLog(req.UserId, req.Remark, req.Quota)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func GetOrganizationTree(c *gin.Context) {
	//db := c.MustGet("db").(*gorm.DB)
	//userID := c.MustGet("userID").(uint)
	//userRole := c.MustGet("userRole").(string)

	loginUser, exists := c.Get("loginUser")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "此接口必须登录"})
		return
	}
	// 将 loginUser 转换为你需要的类型
	loginUserObj := loginUser.(*model.User)

	tenantIdStr := c.Query("tenantId")

	myTenantId := loginUserObj.TenantId
	if tenantIdStr == "" {

	} else {
		tenantId, _ := strconv.Atoi(tenantIdStr)
		if loginUserObj.IsOnProm != 1 {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "无权使用此接口"})
			return
		}
		myTenantId = tenantId
	}

	var users []model.User
	//model.DB.Find(&units)

	model.DB.Where("tenant_id = ? and status != 3", myTenantId).Find(&users)

	// 创建一个 UnitDTO 切片，用于存储转换后的数据
	unitDTOs := make([]model.UnitDTO, len(users))
	// 遍历 users 切片并转换每个 User 为 UnitDTO
	for i, user := range users {
		unitDTOs[i] = model.ToUnitDTO(&user)
	}

	var tree []model.UnitDTO

	if loginUserObj.TenantId == loginUserObj.Id {
		// 租户顶级账号返回完整树
		tree = model.BuildTree(unitDTOs, 0)
		//tree = model.BuildTree(unitDTOs, loginUserObj.TenantId)
	} else {
		//// 普通用户返回自己所在分支和下级完整树
		//var userUnit model.UnitDTO
		//model.DB.First(&userUnit, loginUserObj.Id)
		//
		//var branch []model.UnitDTO
		//currentID := userUnit.Id
		//for currentID != 0 {
		//	var unit model.UnitDTO
		//	model.DB.First(&unit, currentID)
		//	branch = append([]model.UnitDTO{unit}, branch...)
		//	currentID = unit.ParentsId
		//}
		//
		//subTree := model.BuildTree(unitDTOs, userUnit.Id)
		//tree = append(branch, subTree...)

		//subTree := model.BuildTree(unitDTOs, userUnit.Id)
		//tree = append(branch, subTree...)

		var unit model.User
		model.DB.First(&unit, loginUserObj.ParentsId)

		fmt.Println("OUTree.ParentsId", unit.ParentsId)
		fmt.Println("loginUserObj.ParentsId", loginUserObj.ParentsId)
		tree = model.BuildTree(unitDTOs, unit.ParentsId)
		if len(tree) > 0 {
			//tree =
			idToFind := loginUserObj.ParentsId
			var foundNode *model.UnitDTO

			// Anonymous recursive function to find the node by ID
			var findNode func(node *model.UnitDTO, id int) *model.UnitDTO
			findNode = func(node *model.UnitDTO, id int) *model.UnitDTO {
				if node.Id == id {
					return node
				}
				for _, child := range node.Children {
					if found := findNode(&child, id); found != nil {
						return found
					}
				}
				return nil
			}

			// Iterate through the tree and use the anonymous function
			for _, node := range tree {
				if foundNode = findNode(&node, idToFind); foundNode != nil {
					break
				}
			}

			if foundNode != nil {
				fmt.Printf("Node found: %+v\n", foundNode)

				tree = []model.UnitDTO{*foundNode}
			} else {
				fmt.Println("Node not found")
				tree = []model.UnitDTO{}
			}

		}
		//tree = model.BuildTree(unitDTOs, loginUserObj.ParentsId)

	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    tree,
	})
}

type wecomCorpInfoRequest struct {
	CorpId     string `json:"corpId"`
	CorpSecret string `json:"corpSecret"`
}

func SaveWecomCorpInfo(c *gin.Context) {
	loginUser, exists := c.Get("loginUser")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "此接口必须登录"})
		return
	}
	// 将 loginUser 转换为你需要的类型
	loginUserObj := loginUser.(*model.User)

	req := wecomCorpInfoRequest{}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	_ = loginUserObj.UpdateCorpIdAndSecret(req.CorpId, req.CorpSecret)
	at, expireTimestamp, _ := model.GetAccessToken(req.CorpId, req.CorpSecret)
	_ = loginUserObj.UpdateAccessToken(at, expireTimestamp)

	//err = model.Save(req.UserId, int64(req.Quota))
	//if err != nil {
	//	c.JSON(http.StatusOK, gin.H{
	//		"success": false,
	//		"message": err.Error(),
	//	})
	//	return
	//}
	//if req.Remark == "" {
	//	req.Remark = fmt.Sprintf("通过 API 充值 %s", common.LogQuota(int64(req.Quota)))
	//}
	//model.RecordTopupLog(req.UserId, req.Remark, req.Quota)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"accessToken":       at,
			"accessTokenExpire": expireTimestamp,
		},
	})
	return
}

func GetDept(c *gin.Context) {
	loginUser, exists := c.Get("loginUser")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "此接口必须登录"})
		return
	}
	// 将 loginUser 转换为你需要的类型
	loginUserObj := loginUser.(*model.User)

	idStr := c.Query("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "Invalid id"})
		return
	}

	fmt.Print("id: ", id, "\n")

	dept, err := model.GetTenantDeptById(loginUserObj.TenantId, id, false)

	//id := c.Param("id")
	//if err != nil {
	//	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//	return
	//}
	//

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	fmt.Print("dept.IsOU: ", dept.IsOU, "; dept.Id: ", dept.Id, "; dept.ParentsId: ", dept.TenantId, "\n")

	if dept.Id == dept.TenantId {
		// 租户顶级用户
	} else if dept.IsOU == 1 {
		// 部门标签
	} else {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无法获取部门",
		})
		return
	}

	_deptDTO, _err := model.GetDeptWithChildren(dept)

	if _err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   _err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    _deptDTO,
	})

	return
}

func TransferQuota(c *gin.Context) {
	var err error

	var request struct {
		FromUserID  int   `json:"from_user_id"`
		ToUserID    int   `json:"to_user_id"`
		QuotaAmount int64 `json:"quota_amount"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}
	//
	//maxRetries := 5
	//for i := 0; i < maxRetries; i++ {
	err = model.DB.Transaction(func(tx *gorm.DB) error {
		var fromUser, toUser model.User

		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fromUser, request.FromUserID).Error; err != nil {
			return err
		}

		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&toUser, request.ToUserID).Error; err != nil {
			return err
		}

		// 检查 FromUser 是否存在
		if err := tx.First(&fromUser, request.FromUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("FromUser with ID %d not found", request.FromUserID)
			}
			return fmt.Errorf("failed to query FromUser: %w", err)
		}

		// 检查 ToUser 是否存在
		if err := tx.First(&toUser, request.ToUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("ToUser with ID %d not found", request.ToUserID)
			}
			return fmt.Errorf("failed to query ToUser: %w", err)
		}

		//if fromUser.Quota < request.QuotaAmount {
		//	return fmt.Errorf("insufficient quota")
		//}
		//
		//if fromUser.Quota-request.QuotaAmount < fromUser.UsedQuota {
		//	return fmt.Errorf("cannot transfer quota below used quota")
		//}

		//currentTime := time.Now()

		// 更新时检查时间戳
		fmt.Print("request.FromUserID", request.FromUserID, "request.ToUserID", request.ToUserID, "request.QuotaAmount", request.QuotaAmount, "\n")

		//if err := tx.Model(&model.User{}).Where("id = ?", request.FromUserID, fromUser.UpdatedAt).Updates(map[string]interface{}{
		if err0 := tx.Model(&model.User{}).Where("id = ?", request.FromUserID).Updates(map[string]interface{}{
			"quota": gorm.Expr("quota - ?", request.QuotaAmount),
			//"updated_at": currentTime,
		}).Error; err0 != nil {
			return err0
		}

		if err1 := tx.Model(&model.User{}).Where("id = ?", request.ToUserID).Updates(map[string]interface{}{
			"quota": gorm.Expr("quota + ?", request.QuotaAmount),
			//"updated_at": currentTime,
		}).Error; err1 != nil {
			return err1
		}

		return nil
	})

	//if err == nil {
	//	break
	//}

	// 简单重试机制
	//time.Sleep(time.Millisecond * 100)
	//}

	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}
