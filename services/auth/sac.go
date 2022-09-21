package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	cfg "code.gitea.io/gitea/modules/setting"
)

type SacUserResult struct {
	Authenticated      bool `json:authenticated`
	UserAuthentication struct {
		Principal struct {
			Said     int64  `json:said`
			Username string `json:username`
			Nickname string `json:nickname`
		}
	} `json:userAuthentication`
}

func SacAuth(code string) (string) {
	// 取token
	httpauth := []byte(fmt.Sprintf("%s:%s", cfg.SacClientID, cfg.SacClientSecret))
	param := url.Values{}
	param.Add("grant_type", "authorization_code")
	param.Add("code", code)
	param.Add("redirect_uri", cfg.AppURL+"user/sac_login")
	req, err := http.NewRequest("POST", cfg.SacPrivateUrl+"/oauth/token", strings.NewReader(param.Encode()))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(httpauth))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var r map[string]interface{}
	err = dec.Decode(&r)
	if err != nil {
		return ""
	}

	// 找token
	accessToken := r["access_token"]
	if accessToken == nil {
		return ""
	}

	// 查用户
	req, err = http.NewRequest("GET", cfg.SacPrivateUrl+"/api/userinfo", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken.(string))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	userInfo := &SacUserResult{}
	dec = json.NewDecoder(resp.Body)
	err = dec.Decode(userInfo)
	if err != nil {
		return ""
	}

	// 看用户
	if !userInfo.Authenticated {
		return ""
	}

	return userInfo.UserAuthentication.Principal.Username
}
