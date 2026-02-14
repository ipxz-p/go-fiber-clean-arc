package entity

import (
	"time"
	
	"gorm.io/gorm"
)

type User struct {
	ID        int64     
	Email     string    
	Username  string    
	Password  string    
	CreatedAt time.Time 
	UpdatedAt time.Time 
	DeletedAt gorm.DeletedAt 
}
