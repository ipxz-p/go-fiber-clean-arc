package entity

import "time"

type RefreshToken struct {
	ID        int64     
	UserID    int64     
	Token     string    
	ExpiresAt time.Time 
	Revoked   bool      
	CreatedAt time.Time
}
