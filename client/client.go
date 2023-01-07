package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	// "fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	UserKey []byte
	UserPubKey userlib.PKEEncKey
	UserSecKey userlib.PKEDecKey
	UserDSSignKey userlib.DSSignKey
	UserDSVerifyKey userlib.DSVerifyKey
	UserAccessControlUUID uuid.UUID
}

type UserAccessControl struct {
	FileKeyStructUUIDMap map[string]uuid.UUID // maps file name to key struct (knows the location of file and key)
	FileKeyKeyMap map[string][]byte // maps file name to key unlocking Key Struct
	OwnedFiles []string // list of file names owned by user
	InvitationUUIDMap map[string]uuid.UUID // maps file name to UUIDs of invites
	InvitationRecipientMap map[string][]string // immediate invitees (children) of the owner 
	InvitationKeyStructMap map[string]uuid.UUID // location of keystruct duplicates for invitees (recipient usernamte + filename as key)
	InvitationKeyMap map[string][]byte // key to access keystruct of direct invitee (recipient usernamte + filename as key)
}

type Key struct {
	FileUUID uuid.UUID // location of File Struct
	FileKey []byte // key to open file
}

type File struct {
	TailBlockUUID uuid.UUID
	BlockKey []byte // to unlock all blocks
}

type Block struct {
	BlockUUID uuid.UUID
	Content []byte
	PrevBlockUUID uuid.UUID
}

type Invitation struct {
	InviteeKeyStructUUID uuid.UUID // duplicate key stuct
	InviteeKeyStructKey []byte // key to access key struct copy
}

// NOTE: The following methods have toy (insecure!) implementations.

func encryptMAC(item []byte, key []byte) (maccipher []byte, err error) {
	encKey, err := userlib.HashKDF(key, []byte ("encryption"))
	if err != nil { return nil, err }

	macKey, err := userlib.HashKDF(key, []byte ("mac"))
	if err != nil { return nil, err }

	ciphertext := userlib.SymEnc(encKey[:16], userlib.RandomBytes(16), item)
	mac, err := userlib.HMACEval(macKey[:16], ciphertext)
	if err != nil { return nil, err }
	maccipher = append(mac, ciphertext...)

	return maccipher, nil
}

func MACDecrypt(maccipher []byte, key []byte) (plaintext []byte, err error) {
	encKey, err := userlib.HashKDF(key, []byte ("encryption"))
	if err != nil { return nil, err }

	macKey, err := userlib.HashKDF(key, []byte ("mac"))
	if err != nil { return nil, err }

	oldMac := maccipher[:64]
	ciphertext := maccipher[64:]
	newMac, err := userlib.HMACEval(macKey[:16], ciphertext)
	if err != nil { return nil, err }

	if (userlib.HMACEqual(oldMac, newMac)) {
		plaintext = userlib.SymDec(encKey[:16], ciphertext)
	}

	return plaintext, nil
}

func PKEDS(item []byte, pkeEncKey userlib.PKEEncKey, dsSignKey userlib.DSSignKey) (dkedsCipher []byte, err error) {
	encryptedItem, err := userlib.PKEEnc(pkeEncKey, item)
	if err != nil { return nil, err }

	signature, err := userlib.DSSign(dsSignKey, encryptedItem)
	if err != nil { return nil, err }

	dkedsCipher = append(signature, encryptedItem...)

	return dkedsCipher, nil
}

func DSPKD(dkedsCipher []byte, pkeDecKey userlib.PKEDecKey, dsVerifyKey userlib.DSVerifyKey) (plaintext []byte, err error) {
	signature := dkedsCipher[:256]
	encryptedItem := dkedsCipher[256:]

	err = userlib.DSVerify(dsVerifyKey, encryptedItem, signature)
	if err != nil { return nil, err }

	plaintext, err = userlib.PKEDec(pkeDecKey, encryptedItem)
	if err != nil { return nil, err }

	return plaintext, nil
}

func (userdata *User) getUserAccessControl() (userAccessControlData UserAccessControl, err error) {
	encryptedUserAccessControl, ok := userlib.DatastoreGet(userdata.UserAccessControlUUID)
	if !ok { return userAccessControlData, errors.New(strings.ToTitle("user access control not found"))}

	byteUserAccessControl, err := MACDecrypt(encryptedUserAccessControl, userdata.UserKey)
	if err != nil { return userAccessControlData, err }

	err = json.Unmarshal(byteUserAccessControl, &userAccessControlData)
	if err != nil { return userAccessControlData, err }

	return userAccessControlData, nil
}

func (userdata *User) getFileKey(filename string) (fileKey []byte, err error) {
	userAccessControlData, err := userdata.getUserAccessControl()
	if err != nil { return nil, err }

	keyUUID := userAccessControlData.FileKeyStructUUIDMap[filename]
	encryptedKeyStruct, ok := userlib.DatastoreGet(keyUUID)
	if !ok { return nil, errors.New(strings.ToTitle("encrypted key struct not found"))}

	byteKeyStruct, err := MACDecrypt(encryptedKeyStruct, userAccessControlData.FileKeyKeyMap[filename])
	if err != nil { return byteKeyStruct, err }

	var fileKeyStruct Key
	err = json.Unmarshal(byteKeyStruct, &fileKeyStruct)
	if err != nil { return byteKeyStruct, err }
	
	fileKey = fileKeyStruct.FileKey

	return fileKey, nil
}

func (userdata *User) getFileUUID(filename string) (fileUUID uuid.UUID, err error) {
	userAccessControlData, err := userdata.getUserAccessControl()
	if err != nil { return fileUUID, err }

	keyUUID := userAccessControlData.FileKeyStructUUIDMap[filename]
	encryptedKeyStruct, ok := userlib.DatastoreGet(keyUUID)
	if !ok { return fileUUID, errors.New(strings.ToTitle("encrypted key struct not found"))}

	byteKeyStruct, err := MACDecrypt(encryptedKeyStruct, userAccessControlData.FileKeyKeyMap[filename])
	if err != nil { return fileUUID, err }

	var fileKeyStruct Key
	err = json.Unmarshal(byteKeyStruct, &fileKeyStruct)
	if err != nil { return fileUUID, err }

	return fileKeyStruct.FileUUID, err
}

func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}


// ======================================================================================================================================

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 { return nil, errors.New(strings.ToTitle("username should have at least a length of 1 character"))}

	// create User
	var userdata User
	userdata.Username = username

	// generate UserUUID
	byteUsername, err := json.Marshal(username)
	if err != nil { return nil, err }
	userUUID, err := uuid.FromBytes(userlib.Hash(byteUsername)[:16])
	if err != nil { return nil, err }

	_, ok := userlib.DatastoreGet(userUUID)
	if ok { return nil, errors.New("username already exists, entry matching UUID found in Datastore") }
	
	// generate keys for user
	bytePassword, err := json.Marshal(password)
	if err != nil { return nil, err }
	userdata.UserKey = userlib.Argon2Key(bytePassword, byteUsername, 64)[:16]
	userdata.UserPubKey, userdata.UserSecKey, err = userlib.PKEKeyGen()
	if err != nil { return nil, err }
	userdata.UserDSSignKey, userdata.UserDSVerifyKey, err = userlib.DSKeyGen()
	if err != nil { return nil, err }
	userlib.KeystoreSet(userdata.Username + "PKEPubKey", userdata.UserPubKey) // todo: check if username can be seen
	userlib.KeystoreSet(userdata.Username + "DSVerifyKey", userdata.UserDSVerifyKey)

	// generate UserAccessControl and save into Datastore
	var userAccessControlData UserAccessControl
	userdata.UserAccessControlUUID, err = uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil { return nil, err }
	// userAccessControlData.FileUUIDMap = make(map[string] uuid.UUID)
	userAccessControlData.FileKeyStructUUIDMap = make(map[string] uuid.UUID)
	userAccessControlData.FileKeyKeyMap = make(map[string] []byte)
	userAccessControlData.InvitationUUIDMap = make(map[string] uuid.UUID)
	userAccessControlData.InvitationRecipientMap = make(map[string] []string)
	userAccessControlData.InvitationKeyStructMap = make(map[string] uuid.UUID)
	userAccessControlData.InvitationKeyMap = make(map[string] []byte)
	userAccessControlData.OwnedFiles = []string{}

	byteUserAccessControlData, err := json.Marshal(userAccessControlData)
	if err != nil { return nil, err }
	encryptedUserAccessControlData, err := encryptMAC(byteUserAccessControlData, userdata.UserKey)
	if err != nil { return nil, err }
	userlib.DatastoreSet(userdata.UserAccessControlUUID, encryptedUserAccessControlData)

	// save User into Datastore
	byteUser, err := json.Marshal(userdata)
	if err != nil { return nil, err }
	encryptedUser, err := encryptMAC(byteUser, userdata.UserKey)
	if err != nil { return nil, err }
	userlib.DatastoreSet(userUUID, encryptedUser)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// generate UserUUID
	byteUsername, err := json.Marshal(username)
	if err != nil { return nil, err }
	userUUID, err := uuid.FromBytes(userlib.Hash(byteUsername)[:16])
	if err != nil { return nil, err }

	// generate UserKey
	bytePassword, err := json.Marshal(password)
	if err != nil { return nil, err }
	userKey := userlib.Argon2Key(bytePassword, byteUsername, 64)[:16]

	// get User from Datastore
	encryptedUser, ok := userlib.DatastoreGet(userUUID)
	if !ok { return nil, errors.New(strings.ToTitle("user not found"))}
	byteUser, err := MACDecrypt(encryptedUser, userKey)
	if err != nil { return nil, err }
	err = json.Unmarshal(byteUser, &userdata)
	if err != nil { return nil, err }

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// get UserAccessControl from Datastore
	var userAccessControlData UserAccessControl
	encryptedUserAccessControl, ok := userlib.DatastoreGet(userdata.UserAccessControlUUID)
	if !ok { return errors.New(strings.ToTitle("user access control not found"))}
	byteUserAccessControl, err := MACDecrypt(encryptedUserAccessControl, userdata.UserKey)
	if err != nil { return err }
	err = json.Unmarshal(byteUserAccessControl, &userAccessControlData)
	if err != nil { return err }

	// generate Key struct for new file
	var fileKey Key
	keyUUID := uuid.New()
	fileKey.FileKey = userlib.RandomBytes(16) 

	// generate FileUUID, store in Key struct and file
	var filedata File
	fileUUID := uuid.New()
	fileKey.FileUUID = fileUUID

	// generate block key
	filedata.BlockKey = userlib.RandomBytes(16)

	// append new file name to list of owned files in user access control
	userAccessControlData.OwnedFiles = append(userAccessControlData.OwnedFiles, filename)

	// store Key struct and it's key in access control
	userAccessControlData.FileKeyStructUUIDMap[filename] = keyUUID // todo: check if filename exists, then we will need to overwrite
	keyStructKey := userlib.RandomBytes(16)
	userAccessControlData.FileKeyKeyMap[filename] = keyStructKey

	// save Key struct into Datastore
	byteKey, err := json.Marshal(fileKey)
	if err != nil { return err }
	encryptedKeyStruct, err := encryptMAC(byteKey, keyStructKey)
	if err != nil { return err }
	userlib.DatastoreSet(keyUUID, encryptedKeyStruct)


	// save UserAccessControl into Datastore
	byteUserAccessControlData, err := json.Marshal(userAccessControlData)
	if err != nil { return err }
	encryptedUserAccessControlData, err := encryptMAC(byteUserAccessControlData, userdata.UserKey)
	if err != nil { return err }
	userlib.DatastoreSet(userdata.UserAccessControlUUID, encryptedUserAccessControlData)
	
	// create Block and save into Datastore
	var blockdata Block
	blockdata.BlockUUID = uuid.New()
	blockdata.Content = content
	blockdata.PrevBlockUUID = blockdata.BlockUUID
	byteBlock, err := json.Marshal(blockdata)
	if err != nil { return err }
	encryptedBlock, err := encryptMAC(byteBlock, filedata.BlockKey)
	if err != nil { return err }
	userlib.DatastoreSet(blockdata.BlockUUID, encryptedBlock)


	// update TailBlockUUID of the File and save into Datastore
	filedata.TailBlockUUID = blockdata.BlockUUID
	byteFile, err := json.Marshal(filedata)
	if err != nil { return err }
	encryptedFile, err := encryptMAC(byteFile, fileKey.FileKey)
	if err != nil { return err }
	userlib.DatastoreSet(fileUUID, encryptedFile)

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	fileKey, err := userdata.getFileKey(filename)
	if err != nil { return err }

	// get existing filedata
	var filedata File
	fileUUID, err := userdata.getFileUUID(filename)
	if err != nil { return err }
	encryptedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok { return errors.New(strings.ToTitle("file not found"))}
	byteFile, err := MACDecrypt(encryptedFile, fileKey)
	if err != nil { return err }
	err = json.Unmarshal(byteFile, &filedata)
	if err != nil { return err }

	// create new block
	var newBlock Block
	newBlock.BlockUUID = uuid.New()
	newBlock.PrevBlockUUID = filedata.TailBlockUUID
	newBlock.Content = content
	byteBlock, err := json.Marshal(newBlock)
	if err != nil { return err }
	encryptedBlock, err := encryptMAC(byteBlock, filedata.BlockKey)
	if err != nil { return err }
	userlib.DatastoreSet(newBlock.BlockUUID, encryptedBlock)

	// change TailBlockUUID and save back into Datastore
	filedata.TailBlockUUID = newBlock.BlockUUID
	byteFile, err = json.Marshal(filedata)
	if err != nil { return err }
	encryptedFile, err = encryptMAC(byteFile, fileKey)
	if err != nil { return err }
	userlib.DatastoreSet(fileUUID, encryptedFile)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	fileKey, err := userdata.getFileKey(filename)
	if err != nil { return nil, err }

	// load file
	var filedata File
	fileUUID, err := userdata.getFileUUID(filename)
	if err != nil { return nil, err }
	encryptedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok { return nil, errors.New(strings.ToTitle("file not found"))}
	byteFile, err := MACDecrypt(encryptedFile, fileKey)
	if err != nil { return nil, err }
	err = json.Unmarshal(byteFile, &filedata)

	// load blocks
	var curBlock Block
	prevBlockUUID := filedata.TailBlockUUID
	for prevBlockUUID != curBlock.BlockUUID {
		encryptedBlock, ok := userlib.DatastoreGet(prevBlockUUID)
		if !ok { return nil, errors.New(strings.ToTitle("block not found"))}
		byteBlock, err := MACDecrypt(encryptedBlock, filedata.BlockKey)
		if err != nil { return nil, err }
		err = json.Unmarshal(byteBlock, &curBlock)
		if err != nil { return nil, err }
		content = append(curBlock.Content, content...)
		prevBlockUUID = curBlock.PrevBlockUUID
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	var invitationdata Invitation
	// identifier for the the invitation
	invitationUUID := uuid.New()

	// do not allow invites to self
	if (userdata.Username == recipientUsername) { return invitationPtr, errors.New(strings.ToTitle("user trying to invite self")) }

	// get UserAccessControl of inviter
	var userAccessControlData UserAccessControl
	encryptedUserAccessControl, ok := userlib.DatastoreGet(userdata.UserAccessControlUUID)
	if !ok { return invitationPtr, errors.New(strings.ToTitle("user access control not found"))}
	byteUserAccessControl, err := MACDecrypt(encryptedUserAccessControl, userdata.UserKey)
	if err != nil { return invitationPtr, err }
	err = json.Unmarshal(byteUserAccessControl, &userAccessControlData)
	if err != nil { return invitationPtr, err }

	// do not allow invites if user does not have access to file
	_, ok = userAccessControlData.FileKeyStructUUIDMap[filename]
	if !ok { return invitationPtr, errors.New(strings.ToTitle("user does not have access to file")) }

	// inviter owns the file
	if stringInSlice(filename, userAccessControlData.OwnedFiles){
		// create duplciate key struct 

		// get original key struct
		origFileKey, err := userdata.getFileKey(filename)
		if err != nil { return invitationPtr ,err }
		origFileUUID, err := userdata.getFileUUID(filename)
		if err != nil { return invitationPtr, err }

		// generate duplicate Key struct
		var dupeFileKey Key
		dupeFileKey.FileKey = origFileKey
		dupeFileKey.FileUUID = origFileUUID

		// generate new uuid for dupe key struct to store in db
		dupeKeyUUID := uuid.New()
		// generate new key for keys truct
		dupeKeyStructKey := userlib.RandomBytes(16)

		byteDupeFileKey, err := json.Marshal(dupeFileKey)
		if err != nil { return invitationPtr, err }
		encryptedDupeFileKey, err := encryptMAC(byteDupeFileKey, dupeKeyStructKey)
		if err != nil { return invitationPtr, err }
		userlib.DatastoreSet(dupeKeyUUID, encryptedDupeFileKey)

		// add to original user's access control invitation name, access and key maps **
		userAccessControlData.InvitationUUIDMap[filename + recipientUsername] = invitationUUID
		userAccessControlData.InvitationRecipientMap[filename] = append(userAccessControlData.InvitationRecipientMap[filename], recipientUsername)
		userAccessControlData.InvitationKeyStructMap[recipientUsername+filename] = dupeKeyUUID
		userAccessControlData.InvitationKeyMap[recipientUsername+filename] = dupeKeyStructKey

		// generate invitation
		keyStructUUID := dupeKeyUUID
		invitationdata.InviteeKeyStructUUID = keyStructUUID
		invitationdata.InviteeKeyStructKey = dupeKeyStructKey

	}else{ // not the original owner of file sending invite
		invitationdata.InviteeKeyStructUUID = userAccessControlData.FileKeyStructUUIDMap[filename]
		invitationdata.InviteeKeyStructKey = userAccessControlData.FileKeyKeyMap[filename]
	}

	// save useraccesscontrol into Datastore
	byteUserAccessControlData, err := json.Marshal(userAccessControlData)
	if err != nil { return invitationPtr, err }
	encryptedUserAccessControlData, err := encryptMAC(byteUserAccessControlData, userdata.UserKey)
	if err != nil { return invitationPtr, err }
	userlib.DatastoreSet(userdata.UserAccessControlUUID, encryptedUserAccessControlData)

	// find the recipient's public key from Keystore
	recipientPubKey, ok := userlib.KeystoreGet(recipientUsername + "PKEPubKey")
	if !ok { return invitationPtr, errors.New(strings.ToTitle("recipientPubKey not found"))}

	// encrypt the invitation struct with the inviter's public key, signed by the inviter's private key
	byteInvitation, err := json.Marshal(invitationdata)
	if err != nil { return invitationPtr, err }
	pkedInvitation, err := PKEDS(byteInvitation, recipientPubKey, userdata.UserDSSignKey)
	if err != nil { return invitationPtr, err }

	userlib.DatastoreSet(invitationUUID, pkedInvitation)
	
	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// find invitation
	var invitationdata Invitation
	pkedInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok { return errors.New(strings.ToTitle("invitation not found")) }
	

	// find sender DSVerifyKey
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "DSVerifyKey")
	if !ok { return errors.New(strings.ToTitle("senderVerifyKey not found")) }

	// get KeyStructUUID and key
	byteInvitationdata, err := DSPKD(pkedInvitation, userdata.UserSecKey, senderVerifyKey)
	if err != nil { return err }
	err = json.Unmarshal(byteInvitationdata, &invitationdata)
	if err != nil { return err }

	// update file maps for user
	var userAccessControlData UserAccessControl
	encryptedUserAccessControl, ok := userlib.DatastoreGet(userdata.UserAccessControlUUID)
	if !ok { return errors.New(strings.ToTitle("user access control not found"))}
	byteUserAccessControl, err := MACDecrypt(encryptedUserAccessControl, userdata.UserKey)
	if err != nil { return err }
	err = json.Unmarshal(byteUserAccessControl, &userAccessControlData)
	if err != nil { return err }
	userAccessControlData.FileKeyStructUUIDMap[filename] = invitationdata.InviteeKeyStructUUID
	userAccessControlData.FileKeyKeyMap[filename] = invitationdata.InviteeKeyStructKey

	// save UserAccessControl into Datastore
	byteUserAccessControlData, err := json.Marshal(userAccessControlData)
	if err != nil { return err }
	encryptedUserAccessControlData, err := encryptMAC(byteUserAccessControlData, userdata.UserKey)
	if err != nil { return err }
	userlib.DatastoreSet(userdata.UserAccessControlUUID, encryptedUserAccessControlData)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// generate new file key and fileUUID for FILE STRUC
	newFileKey := userlib.RandomBytes(16)
	newFileUUID := uuid.New()

	// move file struct under new file UUID
	// get existing filedata
	origFileKey, err := userdata.getFileKey(filename)
	if err != nil { return err }
	// load file - only need byte data of file
	origFileUUID, err := userdata.getFileUUID(filename)
	if err != nil { return err }

	encryptedFile, ok := userlib.DatastoreGet(origFileUUID)
	if !ok { return errors.New(strings.ToTitle("file not found"))}
	byteFile, err := MACDecrypt(encryptedFile, origFileKey)
	if err != nil { return err }

	// remove old file Struct, re-encrypt file struct with new file key and store in data store with new FileUUID
	userlib.DatastoreDelete(origFileUUID)
	encryptedNewFile, err := encryptMAC(byteFile, newFileKey)
	if err != nil { return err }
	userlib.DatastoreSet(newFileUUID, encryptedNewFile)

	// get UserAccessControl of inviter
	var userAccessControlData UserAccessControl
	encryptedUserAccessControl, ok := userlib.DatastoreGet(userdata.UserAccessControlUUID)
	if !ok { return errors.New(strings.ToTitle("user access control not found"))}
	byteUserAccessControl, err := MACDecrypt(encryptedUserAccessControl, userdata.UserKey)
	if err != nil { return err }
	err = json.Unmarshal(byteUserAccessControl, &userAccessControlData)
	if err != nil { return err }

	// do not allow revoke if inviter is not the owner of the file
	if !stringInSlice(filename, userAccessControlData.OwnedFiles) {return errors.New(strings.ToTitle("inviter is not the owner"))}
	// do not allow revoke if recipient has not been invited
	if !stringInSlice(recipientUsername, userAccessControlData.InvitationRecipientMap[filename]) {return errors.New(strings.ToTitle("file has not been shared with recipient"))}

	// delete invitation
	invitationUUID := userAccessControlData.InvitationUUIDMap[filename + recipientUsername]
	userlib.DatastoreDelete(invitationUUID)

	// get key struct **
	var keyStruct Key
	encryptedKeyStruct, ok := userlib.DatastoreGet(userAccessControlData.FileKeyStructUUIDMap[filename])
	if !ok { return errors.New(strings.ToTitle("key struct not found"))}
	byteKeyStruct, err := MACDecrypt(encryptedKeyStruct, userAccessControlData.FileKeyKeyMap[filename])
	if err != nil { return err }
	err = json.Unmarshal(byteKeyStruct, &keyStruct)
	if err != nil { return err }
	

	// find ORIGINAL key struct and update with new file key and fileUUID
	keyStruct.FileUUID = newFileUUID
	keyStruct.FileKey = newFileKey

	// save new key struct to data store - SAME LOCATION
	byteKeyStruct, err = json.Marshal(keyStruct)
	if err != nil { return err }
	encryptedNewKeyStruct, err := encryptMAC(byteKeyStruct, userAccessControlData.FileKeyKeyMap[filename])
	if err != nil { return err }
	userlib.DatastoreSet(userAccessControlData.FileKeyStructUUIDMap[filename],encryptedNewKeyStruct )


	// find DUPLICATE key struct and update with new file key and fileUUID for remaining valid users
	recipientIndex := -1
	for i, user := range userAccessControlData.InvitationRecipientMap[filename]{
		if user != recipientUsername{
			var oldKeyStruct Key

			keyStructUUID := userAccessControlData.InvitationKeyStructMap[user + filename]
			keyStructKey := userAccessControlData.InvitationKeyMap[user + filename]

			encryptedOldKeyStruct, ok := userlib.DatastoreGet(keyStructUUID)
			if !ok { return errors.New(strings.ToTitle("key struct not found"))}
			byteOldKeyStruct, err := MACDecrypt(encryptedOldKeyStruct, keyStructKey)
			if err != nil { return err }
			err = json.Unmarshal(byteOldKeyStruct, &oldKeyStruct)
			if err != nil { return err }

			oldKeyStruct.FileUUID = newFileUUID
			oldKeyStruct.FileKey = newFileKey

			// save new key struct to data store
			byteNewKeyStruct, err := json.Marshal(oldKeyStruct)
			if err != nil { return err }
			encryptedNewKeyStruct, err := encryptMAC(byteNewKeyStruct, keyStructKey)
			if err != nil { return err }
			userlib.DatastoreSet(keyStructUUID, encryptedNewKeyStruct)
		} else {
			recipientIndex = i
		}
	}
	if (recipientIndex != -1) {
		userAccessControlData.InvitationRecipientMap[filename] = append(userAccessControlData.InvitationRecipientMap[filename][:recipientIndex], userAccessControlData.InvitationRecipientMap[filename][recipientIndex+1:]...)
	}
	
	// update access control in datastore
	byteUserAccessControlData, err := json.Marshal(userAccessControlData)
	if err != nil { return nil}
	encryptedUserAccessControlData, err := encryptMAC(byteUserAccessControlData, userdata.UserKey)
	if err != nil { return nil}
	userlib.DatastoreSet(userdata.UserAccessControlUUID, encryptedUserAccessControlData)


	return nil
}