# Cryptographic-File-Sharing-System
End-to-end encrypted file sharing system built in Golang. Uses SHA-512, RSA, HMAC, and PRNG to ensure confidentiality, authenticity and integrity.

## Threat Model

There are two important adversaries who threaten our system: the datastore adversary, and the revoked user adversary. These two adversaries work independenty and do not collaborate.

- Datastore Adversary: we assume that our Datastore is an untrusted 3rd party service. Any adversary who has access to the Datastore is able to perform CRUD operations to the Datastore API.

- Revoked User Adversary: after a user is granted access to a file, they are counted as a trusted party. However, after their access is revoked, we have to ensure that they do not know any information about the files or any future updates at all (e.g. revoked user should not even know if the length of the file changed, if the number of users with access to the file changed, etc).

## System Diagram

<img alt="System Diagram" src="https://user-images.githubusercontent.com/8297863/211121746-47da363f-0b4b-40cd-bfc2-631d46cb9073.png">

## User Authentication - Relevant Client API Methods: InitUser, GetUser

### InitUser
userUUID will be determined via uuid.fromBytes(Hash(json.Marshal(username))[:16]). Since the username is unique, this result will serve as the unique identifier for the User struct in Datastore. Given that the password has sufficient entropy, we will use Argon2Key(json.Marshal(password), json.Marshal(username), 64)[:16] to generate a deterministic 16 byte symmetric userKey. Next, we create two pairs of keys for RSA and Digital Signatures. The public keys will be stored in the Keystore for file sharing, while the private keys are stored in the User struct. Additionally, we will also initialize the necessary mappings such as FileKeyStructUUIDMap, FileKeyKeyMap, InvitationUUIDMap, etc. Lastly, by doing encryptMAC(json.Marshal(user), userKey), we will obtain encryptedUser, which we can store in the DataStore as DatastoreSet(userUUID, encryptedUser). This preserves integrity and confidentiality. 

### GetUser
During authentication, we will use the deterministic functions uuid.fromBytes(Hash(username)[:16]) and Argon2Key(json.Marshal(password), json.Marshal(username), 64)[:16] to generate userUUID and userKey respectively. With byteUser = MACDecrypt(encryptedUser, userKey) and json.Unmarshal(byteUser, &userdata), we will be able to obtain the original User struct. This implementation also allows for users to have multiple client instances, as username and password are the only things required for authentication.

### Multiple Client Instances
We encryptMAC(UserAccessControl, userKey) and store the userAccessControlUUID and generated ciphertext into Datastore and userAccessControlUUID in the User struct. This allows users to receive the most updated information on multiple instances since we  just refer to a pointer to the UserAccessControl struct (containing access permissions to his files).

## File Storage and Retrieval - Relevant Client API Methods: StoreFile, LoadFile, AppendToFile

### StoreFile
When a user calls StoreFile(filename, content), we generate 3 random UUIDs (keyUUID, fileUUID, blockUUID) along with 3 random keys (KeyStructKey, FileKey, BlockKey). The keyUUID and KeyStructKey help store the Key struct which contains the fileUUID and FileKey. Since we don’t store the fileKey with any particular user, this allows us to conveniently replace fileKeys during revocation of access. We store the reference to this Key struct and the Key struct’s key with FileKeyStructUUIDMap[filename] = keyUUID and FileKeyKeyMap[filename] = keyStructKey. We then append this new filename to the UserAccessControl’s OwnedFiles for future checking of whether this user is allowed to revoke user access. Next, we use the blockUUID and BlockKey to create and store a block of the file. These blocks will be stored as a reverse linked list, and will be especially useful for appending in the future, since we can just append to the start of the linked list. We ensure that our File struct links to the tail Block with by setting filedata.TailBlockUUID to BlockUUID. Lastly, we have to run encryptMAC() and save 4 structs to the Datastore, namely the new Key, new Block, new File, and amended UserAccessControl.

### AppendToFile
On each append, we MACDecrypt() and unmarshal the File, add a new block to the File, and point the File to the UUID of this last block, similar to a reverse linked list. Lastly, we encryptMAC() and store the File and Block in Datastore.

### LoadFile
Given a filename in the personal namespace of the caller, LoadFile(filename) downloads and returns the content of the corresponding file by indexing into userAccessControl.fileMap with filename to find the corresponding fileUUID and then looking up the corresponding userFileKeyUUID in userAccessControl.keyUUIDMap. User shall then decrypt to obtain the file key in the Datastore with the user’s PKE private key, and lastly run MACDecrypt(fileStruct, fileKey) to obtain the File.

## File Sharing and Revocation - Relevant Client API Methods: CreateInvitation, AcceptInvitation

### CreateInvitation
If the user is the file owner, this function will generate and save a duplicated (and encrypted) fileKey into the Datastore. We also use InvitationUUIDMap, InvitationRecipientMap, InvitationKeyStructMap and InvitationKeyMap to keep track of the invitation. If the user is not the file owner, we just generate the invite using the existing fileKey. This separation of workflow into duplicating the key / using the existing key is crucial for revocation later on. Next, we perform PKEDS(json.Marshal(invitationdata, recipientPubKey, inviteeDSSignKey) to ensure integrity and confidentiality.

### AcceptInvitation
The recipient verifies the invitation using DSPKD(pkedInvitation, userdata.UserSecKey, senderVerifyKey). If the invitation has been verified to be untampered, we will update the UserAccessControl to include pointers to the fileKey and Key struct in FileKeyStructUUIDMap and FileKeyKeyMap respectively. After updating these maps, we encryptMAC() and save the UserAccessControl back into the Datastore.

### RevokeAccess
The owner will generate a new fileKey for the file and proceed to update the file struct by iterating through file.userAccess to remove all children (i.e. users whom the revoked user shared access with) of the revoked user from the list and proceed to update the fileKey for all remaining valid users by accessing their key-value pairs (userFileKeyUUID,fileKey) and perform public key encryption and re-signing the updated fileKey entry with the valid user’s public key and the revokee’s private key.

## Appendix 1: Helper Methods

These helper functions were created because to streamline the implementation of our system. Most of the functionalities of each function is commonly used together, e.g. we would always encrypt then MAC to ensure confidentiality, integrity, and authencity of our data. If we were to encrypt without MAC, that would only ensure confidentiality; and if we were to MAC without encryption, that would only ensure integrity and authenticity. As such, all these helper functions below help to combine cryptographic algorithms that are commonly used together to ensure full security.

#### func encryptMAC(item[]byte, key []byte) (maccipher []byte)
This function first uses the key to derive encKey with HashKDF(userKey, []byte (“encryption”)) and macKey with HashKDF(userKey, []byte(“mac”)). Next, we get our ciphertext by performing encryption on our item (e.g. User, File) with SymEnc(encKey[:16], RandomBytes(16), item). Afterwhich, we MAC the ciphertext with HMACEval(macKey[:16], ciphertext) and concatenate it with the ciphertext, which will be our return value maccipher.

#### func MACDecrypt(maccipher []byte, key []byte) (plaintext []byte)
We first generate encKey and macKey in the same way as in encryptMAC(). Since maccipher is the concatenation of HMAC and the ciphertext, maccipher[64:] should be the original unaltered ciphertext. Hence, HMACEval(macKey[:16], maccipher[64:]) should return the same maccipher. We can check if they are equal with HMACEqual(). If HMACEqual() returns true, we shall perform SymDec(encKey[:16], maccipher[64:]) to obtain the plaintext.

#### func PKEDS(item []byte, pkeEncKey userlib.PKEEncKey, dsSignKey userlib.DSSignKey) (dkedsCipher []byte, err error)
This function is very similar to encryptMAC(), except that we encrypt-then-sign (with asymmetric encryption) instead of encrypt-then-MAC (using symmetric encryption).

#### func DSPKD(dkedsCipher []byte, pkeDecKey userlib.PKEDecKey, dsVerifyKey userlib.DSVerifyKey)
This function is very similar to MACdecrypt(), except that we verify using DS instead of MAC, and decrypt with asymmetric decryption instead of symmetric decryption.

#### func (userdata *User) getUserAccessControl() (userAccessControlData UserAccessControl, err error)
This function returns the UserAccessControl struct of the respective User.

#### func (userdata *User) getFileKey(filename string) (fileKey []byte, err error)
This function returns the fileKey given a User and a filename.

#### func (userdata *User) getFileUUID(filename string) (fileUUID uuid.UUID, err error)
This function returns the fileUUID given a User and a filename.

#### func stringInSlice(a string, list []string) bool
This function checks if a string exists in a list of strings, which will be especially useful in checking for permissions (e.g. for file sharing).

## Acknowledgements

Credits to UC Berkeley CS 161 Computer Security module. More details of the design requirements for this project can be found here: https://fa22.cs161.org/proj2/requirements/
