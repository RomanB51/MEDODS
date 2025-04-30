package main

type User struct {
	Id           string `json:"id"`
	Ip           string `json:"ip"`
	RefreshToken string `json:"refresh"`
	AccessToken  string `json:"access"`
}
