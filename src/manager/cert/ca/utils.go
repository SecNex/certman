package ca

import "fmt"

func preparePath(customerID string, authorityID string, path string) string {
	return fmt.Sprintf("%s/%s/%s", path, customerID, authorityID)
}
