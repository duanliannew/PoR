package main

/*
#cgo CFLAGS: -I../include
#cgo LDFLAGS: -L../build/src -lpor -lstdc++
#include "wrapper.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
	"fmt"
	"flag"
	"path/filepath"
	"net/http"
	"strconv"
	"strings"
	"encoding/json"
	"github.com/gin-gonic/gin"
)

func main() {
	var path string
	flag.StringVar(&path, "p", "", "path to por db")
	flag.Parse()
	if path == "" {
		fmt.Println("Please specify Proof of Preserve DB path: ./app -p path")
		return
	}

	absolutePath, err := filepath.Abs(path)
	if (err != nil) {
		fmt.Println("Wrong resolution for path", path)
		return
	}

	// Load PoR database
	cStrPath := C.CString(absolutePath)
    if 0 == C.LoadDB(cStrPath) {
		fmt.Println("Fail to load Proof of Preserve DB")
		C.free(unsafe.Pointer(cStrPath))
        return
	}
	fmt.Println("Sucessfully load Proof of Preserve DB:", absolutePath)
	C.free(unsafe.Pointer(cStrPath))

	// Start web api service
	r := gin.Default()
    r.GET("/por", func(c *gin.Context) {
		id := c.Query("id")
		userID, err := strconv.ParseUint(id, 10, 64)
		// check if user id is valid
		if (err != nil) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_message": "Invalid ID",
			})

			return
		}

	    cUserID := C.uint64_t(userID)
	    info := C.UserInfo(cUserID)
		// check if we find the user's info
		if (info == nil) {
			c.JSON(http.StatusNotFound, gin.H{
				"error_message": "Not Found",
			})

			return
		}

		// assemble user info
	    gInfo := C.GoString(info)
	    C.free(unsafe.Pointer(info))
		u := ParseUserInfo(gInfo)
		jsonData, _ := json.Marshal(u)
        c.JSON(http.StatusOK, gin.H{
		  "error_message": "Success",
          "user": json.RawMessage(jsonData),
        })
    })
    r.Run()
}

// Parse user info
//(8,8888) 0x6266ab587ef565a55daf01ff5101d1b40b4f4334c9ece68c130fe223a1a37c96
//(left,0x33471d10e51b83e3419eba1f096203264d1e60de57522402827a4de50dee8375) (left,0x03b6089f6b1adf08e6f1b5c7f2eff348e3bcc97903216a726c62f358e97c1df1)
//(left,0xfafe4ecc00e37d340d72f581fbbda4e179ad24bdc2f45713dcc2a38ebfc30439) 0xb1231de33da17c23cebd80c104b88198e0914b0463d0e14db163605b904a7ba3
type user struct {
	ID      uint64 `json:"id"`
	Balance uint64 `json:"balance"`
	Proof   merkleProof `json:"proof"`
}

type merkleNode struct {
	Sibling string `json:"position"`
	Hash    string `json:"node_hash"`
}

type merkleProof struct {
	Root     string `json:"merkle_root"`
	UserHash string `json:"user_hash`
	Path     []merkleNode `json:"merkle_path"`
}

func ParseUserInfo(info string) user {
	var u user
	// seperate each field by white space
	fields := strings.Fields(info)

	// parse user id and balance
	s := strings.Trim(fields[0], "()");
	id_balance := strings.Split(s, ",")
	u.ID, _ = strconv.ParseUint(id_balance[0], 10, 64)
    u.Balance, _ = strconv.ParseUint(id_balance[1], 10, 64)

	// parse user data's hash and merkle root
	u.Proof.UserHash = fields[1];
	u.Proof.Root = fields[len(fields)-1]

	// parse merkle proof path
	for _, s := range fields[2:len(fields)-1] {
		node := strings.Trim(s, "()")
		node_fields := strings.Split(node, ",")
		u.Proof.Path = append(u.Proof.Path, merkleNode{node_fields[0], node_fields[1]})
	}

	return u
}