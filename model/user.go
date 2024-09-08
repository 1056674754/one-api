package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/songquanpeng/one-api/common"
	"github.com/songquanpeng/one-api/common/blacklist"
	"github.com/songquanpeng/one-api/common/config"
	"github.com/songquanpeng/one-api/common/helper"
	"github.com/songquanpeng/one-api/common/logger"
	"github.com/songquanpeng/one-api/common/random"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	RoleGuestUser        = 0
	RoleTenantUser       = 10
	RoleTenantAdmin      = 80
	RoleTenantSuperAdmin = 90
	RoleSystemAdminUser  = 99
	RoleSystemRootUser   = 100
)

const (
	UserStatusEnabled  = 1 // don't use 0, 0 is the default value!
	UserStatusDisabled = 2 // also don't use 0
	UserStatusDeleted  = 3
)

// User if you add sensitive fields, don't forget to clean them in setupLogin function.
// Otherwise, the sensitive information will be saved on local storage in plain text!
type User struct {
	IsOnProm         int       `json:"is_on_prom" gorm:"type:int;index;default:0" validate:"min=0,max=1"` // new field for saas
	TenantId         int       `json:"tenant_id" gorm:"type:int;index"`                                   // new field for tenant
	TenantDomain     string    `json:"tenant_domain"`                                                     // new field for tenant
	ParentsId        int       `json:"parents_id" gorm:"type:int;index"`                                  // new field for organization
	IsOU             int       `json:"is_ou" gorm:"type:int;index;default:0" validate:"min=0,max=1"`      // new field for organization
	Id               int       `json:"id"`
	Username         string    `json:"username" gorm:"unique;index" validate:"max=24"`
	Password         string    `json:"password" gorm:"not null;" validate:"min=8,max=20"`
	DisplayName      string    `json:"display_name" gorm:"index" validate:"max=20"`
	Role             int       `json:"role" gorm:"type:int;default:1"`   // admin, util
	Status           int       `json:"status" gorm:"type:int;default:1"` // enabled, disabled
	Email            string    `json:"email" gorm:"index" validate:"max=50"`
	GitHubId         string    `json:"github_id" gorm:"column:github_id;index"`
	WeChatId         string    `json:"wechat_id" gorm:"column:wechat_id;index"`
	WecomId          string    `json:"wecom_id" gorm:"column:wecom_id;index"`
	LarkId           string    `json:"lark_id" gorm:"column:lark_id;index"`
	VerificationCode string    `json:"verification_code" gorm:"-:all"`                                    // this field is only for Email verification, don't save it to database!
	AccessToken      string    `json:"access_token" gorm:"type:char(32);column:access_token;uniqueIndex"` // For system management
	Quota            int64     `json:"quota" gorm:"bigint;default:0"`
	UsedQuota        int64     `json:"used_quota" gorm:"bigint;default:0;column:used_quota"` // used quota
	RequestCount     int       `json:"request_count" gorm:"type:int;default:0;"`             // request number
	AffCode          string    `json:"aff_code" gorm:"type:varchar(32);column:aff_code;uniqueIndex"`
	InviterId        int       `json:"inviter_id" gorm:"type:int;column:inviter_id;index"`
	Group            string    `json:"group" gorm:"type:varchar(32);default:'default'"`
	Children         []User    `json:"children" gorm:"-"`
	UpdatedAt        time.Time `json:"updated_at" gorm:"type:datetime;autoUpdateTime"` // 自动更新时间戳
}

type UnitDTO struct {
	IsOnProm     int       `json:"is_on_prom"`
	TenantId     int       `json:"tenant_id"`
	ParentsId    int       `json:"parents_id"`
	IsOU         int       `json:"is_ou"`
	Id           int       `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	Role         int       `json:"role"`
	Status       int       `json:"status"`
	Email        string    `json:"email"`
	GitHubId     string    `json:"github_id"`
	WeChatId     string    `json:"wechat_id"`
	WecomId      string    `json:"wecom_id"`
	LarkId       string    `json:"lark_id"`
	Quota        int64     `json:"quota"`
	UsedQuota    int64     `json:"used_quota"`
	RequestCount int       `json:"request_count"`
	AffCode      string    `json:"aff_code"`
	InviterId    int       `json:"inviter_id"`
	Group        string    `json:"group"`
	Children     []UnitDTO `json:"children"`
}

func ToUnitDTO(user *User) UnitDTO {
	childrenDTO := make([]UnitDTO, len(user.Children))
	for i, child := range user.Children {
		childrenDTO[i] = ToUnitDTO(&child)
	}

	return UnitDTO{
		IsOnProm:     user.IsOnProm,
		TenantId:     user.TenantId,
		ParentsId:    user.ParentsId,
		IsOU:         user.IsOU,
		Id:           user.Id,
		Username:     user.Username,
		DisplayName:  user.DisplayName,
		Role:         user.Role,
		Status:       user.Status,
		Email:        user.Email,
		GitHubId:     user.GitHubId,
		WeChatId:     user.WeChatId,
		WecomId:      user.WecomId,
		LarkId:       user.LarkId,
		Quota:        user.Quota,
		UsedQuota:    user.UsedQuota,
		RequestCount: user.RequestCount,
		AffCode:      user.AffCode,
		InviterId:    user.InviterId,
		Group:        user.Group,
		Children:     childrenDTO,
	}
}

func GetMaxUserId() int {
	var user User
	DB.Last(&user)
	return user.Id
}

func GetAllUsers(loginUser *User, startIdx int, num int, order string, rootUserOnly bool) (users []*User, totalCount int64, totalPage int, err error) {
	if loginUser == nil {
		return nil, 0, 0, errors.New("loginUser is nil")
	}

	baseQuery := DB.Model(&User{}).Omit("password").Where(
		"status != ?", UserStatusDeleted)

	if rootUserOnly {
		baseQuery = baseQuery.Where("tenant_id = id")
	}

	if loginUser.IsOnProm != 1 {
		baseQuery = baseQuery.Where("tenant_id = ?", loginUser.TenantId)
	}

	// 计算总记录数
	err = baseQuery.Count(&totalCount).Error
	if err != nil {
		return nil, 0, 0, err
	}

	// 计算总页数
	if num > 0 {
		totalPage = int((totalCount + int64(num) - 1) / int64(num))
	} else {
		totalPage = 0
	}

	// 分页查询
	query := baseQuery.Limit(num).Offset(startIdx)

	switch order {
	case "quota":
		query = query.Order("quota desc")
	case "used_quota":
		query = query.Order("used_quota desc")
	case "request_count":
		query = query.Order("request_count desc")
	default:
		query = query.Order("id desc")
	}

	err = query.Find(&users).Error
	return users, totalCount, totalPage, err
}

func SearchUsers(keyword string) (users []*User, err error) {
	if !common.UsingPostgreSQL {
		err = DB.Omit("password").Where(
			"id = ? or username LIKE ? or email LIKE ? or display_name LIKE ?", keyword, keyword+"%", keyword+"%", keyword+"%").Find(&users).Error
	} else {
		err = DB.Omit("password").Where(
			"username LIKE ? or email LIKE ? or display_name LIKE ?", keyword+"%", keyword+"%", keyword+"%").Find(&users).Error
	}
	return users, err
}

func GetUserById(id int, selectAll bool) (*User, error) {
	if id == 0 {
		return nil, errors.New("id 为空！")
	}
	user := User{Id: id}
	var err error = nil
	if selectAll {
		err = DB.First(&user, "id = ?", id).Error
	} else {
		err = DB.Omit("password").First(&user, "id = ?", id).Error
	}
	return &user, err
}

func GetTenantUserById(tenantId int, id int, selectAll bool) (*User, error) {
	if id == 0 {
		return nil, errors.New("id 为空！")
	}
	user := User{Id: id}
	var err error = nil
	if selectAll {
		err = DB.First(&user, "id = ? AND tenant_id = ? AND is_ou = 0 AND is_on_prom = 0", id, tenantId).Error
	} else {
		err = DB.Omit("password").First(&user, "id = ? AND tenant_id = ? AND is_ou = 0 AND is_on_prom = 0", id, tenantId).Error
	}
	return &user, err
}

func GetTenantDeptById(tenantId int, id int, selectAll bool) (*User, error) {
	if id == 0 {
		return nil, errors.New("id 为空！")
	}
	user := User{Id: id}
	var err error = nil
	if selectAll {
		err = DB.First(&user, "id = ? AND tenant_id = ? AND is_ou = 1 AND is_on_prom = 0", id, tenantId).Error
	} else {
		err = DB.Omit("password").First(&user, "id = ? AND tenant_id = ? AND is_ou = 1 AND is_on_prom = 0", id, tenantId).Error
	}
	return &user, err
}

func GetUserIdByAffCode(affCode string) (int, error) {
	if affCode == "" {
		return 0, errors.New("affCode 为空！")
	}
	var user User
	err := DB.Select("id").First(&user, "aff_code = ?", affCode).Error
	return user.Id, err
}

func DeleteUserById(id int) (err error) {
	if id == 0 {
		return errors.New("id 为空！")
	}
	user := User{Id: id}
	return user.Delete()
}

func (user *User) Insert(inviterId int) error {
	var err error
	if user.Password != "" {
		user.Password, err = common.Password2Hash(user.Password)
		if err != nil {
			return err
		}
	}
	user.Quota = config.QuotaForNewUser
	user.AccessToken = random.GetUUID()
	user.AffCode = random.GetRandomString(4)

	// 开始事务
	tx := DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	// 尝试创建用户
	result := tx.Create(user)
	if result.Error != nil {
		// 如果创建失败，回滚事务
		tx.Rollback()
		return result.Error
	}

	//result := DB.Create(user)
	//if result.Error != nil {
	//	return result.Error
	//}

	//DB.Model(&user).Update("TenantId", user.Id)

	// 更新 TenantId
	if user.TenantId <= 0 && user.IsOnProm == 0 {
		if result := tx.Model(user).Update("TenantId", user.Id); result.Error != nil {
			// 如果更新失败，回滚事务
			tx.Rollback()
			return result.Error
		}
	}
	// 提交事务
	if result := tx.Commit(); result.Error != nil {
		return result.Error
	}

	if config.QuotaForNewUser > 0 {
		RecordLog(user.Id, LogTypeSystem, fmt.Sprintf("新用户注册赠送 %s", common.LogQuota(config.QuotaForNewUser)))
	}
	if inviterId != 0 {
		if config.QuotaForInvitee > 0 {
			_ = IncreaseUserQuota(user.Id, config.QuotaForInvitee)
			RecordLog(user.Id, LogTypeSystem, fmt.Sprintf("使用邀请码赠送 %s", common.LogQuota(config.QuotaForInvitee)))
		}
		if config.QuotaForInviter > 0 {
			_ = IncreaseUserQuota(inviterId, config.QuotaForInviter)
			RecordLog(inviterId, LogTypeSystem, fmt.Sprintf("邀请用户赠送 %s", common.LogQuota(config.QuotaForInviter)))
		}
	}
	// create default token
	cleanToken := Token{
		UserId:         user.Id,
		Name:           "default",
		Key:            random.GenerateKey(),
		CreatedTime:    helper.GetTimestamp(),
		AccessedTime:   helper.GetTimestamp(),
		ExpiredTime:    -1,
		RemainQuota:    -1,
		UnlimitedQuota: true,
	}
	result.Error = cleanToken.Insert()
	if result.Error != nil {
		// do not block
		logger.SysError(fmt.Sprintf("create default token for user %d failed: %s", user.Id, result.Error.Error()))
	}
	return nil
}

func (user *User) Update(updatePassword bool) error {
	var err error
	if updatePassword {
		user.Password, err = common.Password2Hash(user.Password)
		if err != nil {
			return err
		}
	}
	if user.Status == UserStatusDisabled {
		blacklist.BanUser(user.Id)
	} else if user.Status == UserStatusEnabled {
		blacklist.UnbanUser(user.Id)
	}
	err = DB.Model(user).Updates(user).Error
	return err
}

func (user *User) Delete() error {
	if user.Id == 0 {
		return errors.New("id 为空！")
	}
	blacklist.BanUser(user.Id)
	user.Username = fmt.Sprintf("deleted_%s", random.GetUUID())
	user.Status = UserStatusDeleted
	err := DB.Model(user).Updates(user).Error
	return err
}

// ValidateAndFill check password & user status
func (user *User) ValidateAndFill() (err error) {
	// When querying with struct, GORM will only query with non-zero fields,
	// that means if your field’s value is 0, '', false or other zero values,
	// it won’t be used to build query conditions
	password := user.Password
	if user.Username == "" || password == "" {
		return errors.New("用户名或密码为空")
	}

	// Build the query based on TenantId
	var query *gorm.DB
	if user.TenantId > 0 {
		query = DB.Where("username = ? AND tenant_id = ?", user.Username, user.TenantId)
	} else {
		query = DB.Where("username = ? AND (tenant_id = 0 OR id = tenant_id)", user.Username)
	}

	err = query.First(user).Error
	if err != nil {
		// we must make sure check username firstly
		// consider this case: a malicious user set his username as other's email
		if user.TenantId > 0 {
			query = DB.Where("email = ? AND tenant_id = ?", user.Username, user.TenantId)
		} else {
			query = DB.Where("email = ? AND (tenant_id = 0 OR id = tenant_id)", user.Username)
		}

		err := query.First(user).Error
		if err != nil {
			return errors.New("用户名或密码错误，或用户已被封禁")
		}
	}

	okay := common.ValidatePasswordAndHash(password, user.Password)
	if !okay || user.Status != UserStatusEnabled {
		return errors.New("用户名或密码错误，或用户已被封禁")
	}
	return nil
}

func (user *User) FillUserById() error {
	if user.Id == 0 {
		return errors.New("id 为空！")
	}
	DB.Where(User{Id: user.Id}).First(user)
	return nil
}

func (user *User) FillUserByEmail() error {
	if user.Email == "" {
		return errors.New("email 为空！")
	}
	DB.Where(User{Email: user.Email}).First(user)
	return nil
}

func (user *User) FillUserByGitHubId() error {
	if user.GitHubId == "" {
		return errors.New("GitHub id 为空！")
	}
	DB.Where(User{GitHubId: user.GitHubId}).First(user)
	return nil
}

func (user *User) FillUserByLarkId() error {
	if user.LarkId == "" {
		return errors.New("lark id 为空！")
	}
	DB.Where(User{LarkId: user.LarkId}).First(user)
	return nil
}

func (user *User) FillUserByWeChatId() error {
	if user.WeChatId == "" {
		return errors.New("WeChat id 为空！")
	}
	DB.Where(User{WeChatId: user.WeChatId}).First(user)
	return nil
}

func (user *User) FillUserByUsername() error {
	if user.Username == "" {
		return errors.New("username 为空！")
	}
	DB.Where(User{Username: user.Username}).First(user)
	return nil
}

func IsEmailAlreadyTaken(email string) bool {
	return DB.Where("email = ?", email).Find(&User{}).RowsAffected == 1
}

func IsWeChatIdAlreadyTaken(wechatId string) bool {
	return DB.Where("wechat_id = ?", wechatId).Find(&User{}).RowsAffected == 1
}

func IsGitHubIdAlreadyTaken(githubId string) bool {
	return DB.Where("github_id = ?", githubId).Find(&User{}).RowsAffected == 1
}

func IsLarkIdAlreadyTaken(githubId string) bool {
	return DB.Where("lark_id = ?", githubId).Find(&User{}).RowsAffected == 1
}

func IsUsernameAlreadyTaken(username string) bool {
	return DB.Where("username = ?", username).Find(&User{}).RowsAffected == 1
}

func ResetUserPasswordByEmail(email string, password string) error {
	if email == "" || password == "" {
		return errors.New("邮箱地址或密码为空！")
	}
	hashedPassword, err := common.Password2Hash(password)
	if err != nil {
		return err
	}
	err = DB.Model(&User{}).Where("email = ?", email).Update("password", hashedPassword).Error
	return err
}

func IsAdmin(userId int) bool {
	if userId == 0 {
		return false
	}
	var user User
	err := DB.Where("id = ?", userId).Select("role").Find(&user).Error
	if err != nil {
		logger.SysError("no such user " + err.Error())
		return false
	}
	return user.Role >= RoleSystemAdminUser
}

func IsUserEnabled(userId int) (bool, error) {
	if userId == 0 {
		return false, errors.New("user id is empty")
	}
	var user User
	err := DB.Where("id = ?", userId).Select("status").Find(&user).Error
	if err != nil {
		return false, err
	}
	return user.Status == UserStatusEnabled, nil
}

func ValidateAccessToken(token string) (user *User) {
	if token == "" {
		return nil
	}
	token = strings.Replace(token, "Bearer ", "", 1)
	user = &User{}
	if DB.Where("access_token = ?", token).First(user).RowsAffected == 1 {
		return user
	}
	return nil
}

func GetUserQuota(id int) (quota int64, err error) {
	err = DB.Model(&User{}).Where("id = ?", id).Select("quota").Find(&quota).Error
	return quota, err
}

func GetUserUsedQuota(id int) (quota int64, err error) {
	err = DB.Model(&User{}).Where("id = ?", id).Select("used_quota").Find(&quota).Error
	return quota, err
}

func GetUserEmail(id int) (email string, err error) {
	err = DB.Model(&User{}).Where("id = ?", id).Select("email").Find(&email).Error
	return email, err
}

func GetUserGroup(id int) (group string, err error) {
	groupCol := "`group`"
	if common.UsingPostgreSQL {
		groupCol = `"group"`
	}

	err = DB.Model(&User{}).Where("id = ?", id).Select(groupCol).Find(&group).Error
	return group, err
}

func IncreaseUserQuota(id int, quota int64) (err error) {
	if quota < 0 {
		return errors.New("quota 不能为负数！")
	}
	if config.BatchUpdateEnabled {
		addNewRecord(BatchUpdateTypeUserQuota, id, quota)
		return nil
	}
	return increaseUserQuota(id, quota)
}

func increaseUserQuota(id int, quota int64) (err error) {
	err = DB.Model(&User{}).Where("id = ?", id).Update("quota", gorm.Expr("quota + ?", quota)).Error
	return err
}

func DecreaseUserQuota(id int, quota int64) (err error) {
	if quota < 0 {
		return errors.New("quota 不能为负数！")
	}
	if config.BatchUpdateEnabled {
		addNewRecord(BatchUpdateTypeUserQuota, id, -quota)
		return nil
	}
	return decreaseUserQuota(id, quota)
}

func decreaseUserQuota(id int, quota int64) (err error) {
	err = DB.Model(&User{}).Where("id = ?", id).Update("quota", gorm.Expr("quota - ?", quota)).Error
	return err
}

func GetRootUserEmail() (email string) {
	DB.Model(&User{}).Where("role = ?", RoleSystemRootUser).Select("email").Find(&email)
	return email
}

func UpdateUserUsedQuotaAndRequestCount(id int, quota int64) {
	if config.BatchUpdateEnabled {
		addNewRecord(BatchUpdateTypeUsedQuota, id, quota)
		addNewRecord(BatchUpdateTypeRequestCount, id, 1)
		return
	}
	updateUserUsedQuotaAndRequestCount(id, quota, 1)
}

func updateUserUsedQuotaAndRequestCount(id int, quota int64, count int) {
	err := DB.Model(&User{}).Where("id = ?", id).Updates(
		map[string]interface{}{
			"used_quota":    gorm.Expr("used_quota + ?", quota),
			"request_count": gorm.Expr("request_count + ?", count),
		},
	).Error
	if err != nil {
		logger.SysError("failed to update user used quota and request count: " + err.Error())
	}
}

func updateUserUsedQuota(id int, quota int64) {
	err := DB.Model(&User{}).Where("id = ?", id).Updates(
		map[string]interface{}{
			"used_quota": gorm.Expr("used_quota + ?", quota),
		},
	).Error
	if err != nil {
		logger.SysError("failed to update user used quota: " + err.Error())
	}
}

func updateUserRequestCount(id int, count int) {
	err := DB.Model(&User{}).Where("id = ?", id).Update("request_count", gorm.Expr("request_count + ?", count)).Error
	if err != nil {
		logger.SysError("failed to update user request count: " + err.Error())
	}
}

func GetUsernameById(id int) (username string) {
	DB.Model(&User{}).Where("id = ?", id).Select("username").Find(&username)
	return username
}

func BuildTree(units []UnitDTO, parentsId int) []UnitDTO {
	var tree []UnitDTO
	for _, unit := range units {
		if unit.ParentsId == parentsId {
			children := BuildTree(units, unit.Id)

			unit.Children = children
			tree = append(tree, unit)
			//tree = append(tree, children...)
		}
	}
	return tree

	//var children []User
	//if err := DB.Where("parents_id = ?", user.Id).Find(&children).Error; err != nil {
	//	return err
	//}

	//for i := range children {
	//	if children[i].IsOU == 1 {
	//		if err := FetchChildren(&children[i]); err != nil {
	//			return err
	//		}
	//	}
	//}
	//
	//user.Children = children
	//return nil

}

func FetchWeComEmployees(accessToken string) ([]User, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/user/list?access_token=%s&department_id=1&fetch_child=1", accessToken)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode  int    `json:"errcode"`
		ErrMsg   string `json:"errmsg"`
		UserList []struct {
			UserId     string `json:"userid"`
			Name       string `json:"name"`
			Department []int  `json:"department"`
			Email      string `json:"email"`
		} `json:"userlist"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.ErrCode != 0 {
		return nil, fmt.Errorf("WeCom API error: %s", result.ErrMsg)
	}

	var users []User
	for _, u := range result.UserList {
		user := User{
			Username:    u.UserId,
			DisplayName: u.Name,
			Email:       u.Email,
			TenantId:    1, // Example TenantId, adjust as needed
			ParentsId:   u.Department[0],
			IsOU:        0,
		}
		users = append(users, user)
	}

	return users, nil
}

func saveUsersToDB(users []User) error {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	if err := db.AutoMigrate(&User{}); err != nil {
		return err
	}

	for _, user := range users {
		if err := db.Create(&user).Error; err != nil {
			return err
		}
	}

	return nil
}

func GetWecomInfo(topUser User) (string, string, string, int, error) {
	input := topUser.WecomId
	// 使用 strings.Split 函数按分号分割字符串
	parts := strings.Split(input, ";")

	// 检查分割后的部分数量是否足够
	if len(parts) < 4 {
		return "", "", "", 0, errors.New("input string does not contain enough parts")
	}

	// 尝试将 parts[3] 转换为 int
	integerPart, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", "", "", 0, errors.New("parts[3] is not a valid integer")
	}

	// 返回分割后的值
	return parts[0], parts[1], parts[2], integerPart, nil
}

// UpdateCorpIdAndSecret 更新 corpId 和 corpSecret
func (user *User) UpdateCorpIdAndSecret(newCorpId, newCorpSecret string) error {
	parts := strings.Split(user.WecomId, ";")
	if len(parts) != 4 {
		fmt.Println("Invalid WecomId format")
		//return
		parts = strings.Split(";;;", ";")
	}
	parts[0] = newCorpId
	parts[1] = newCorpSecret
	user.WecomId = strings.Join(parts, ";")

	err := DB.Model(user).Updates(user).Error
	return err
}

// UpdateAccessToken 更新 accessToken
func (user *User) UpdateAccessToken(newAccessToken string, expire_at int64) error {
	parts := strings.Split(user.WecomId, ";")
	if len(parts) != 4 {
		fmt.Println("Invalid WecomId format")
		parts = strings.Split(";;;", ";")
	}
	parts[2] = newAccessToken
	parts[3] = strconv.FormatInt(expire_at, 10)
	user.WecomId = strings.Join(parts, ";")

	err := DB.Model(user).Updates(user).Error
	return err
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

func GetAccessToken(corpID, corpSecret string) (string, int64, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s", corpID, corpSecret)

	resp, err := http.Get(url)
	if err != nil {
		return "", 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read response body: %w", err)
	}

	var tokenResponse AccessTokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", 0, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if tokenResponse.ErrCode != 0 {
		return "", 0, fmt.Errorf("error from API: %d - %s", tokenResponse.ErrCode, tokenResponse.ErrMsg)
	}

	// 计算过期时间的时间戳
	expireTimestamp := time.Now().Unix() + int64(tokenResponse.ExpiresIn)

	return tokenResponse.AccessToken, expireTimestamp, nil
}

func GetDeptWithChildren(dept *User) (*UnitDTO, error) {
	//var dept User
	//if err := DB.Where("id = ? AND is_ou = 1", id).First(&dept).Error; err != nil {
	//	return nil, err
	//}

	if err := FetchChildren(dept); err != nil {
		return nil, err
	}

	deptDTO := ToUnitDTO(dept)
	return &deptDTO, nil
}

func FetchChildren(user *User) error {
	var children []User
	if err := DB.Where("parents_id = ? and status != 3", user.Id).Find(&children).Error; err != nil {
		return err
	}

	for i := range children {
		if children[i].IsOU == 1 {
			if err := FetchChildren(&children[i]); err != nil {
				return err
			}
		}
	}

	user.Children = children
	return nil
}
