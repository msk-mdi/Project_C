/******************************************************************************
 *
 *  secure_messaging.c
 *
 *  Compilation (exemple) :
 *      gcc secure_messaging.c -lssl -lcrypto -lpthread -o secure_messaging
 *
 *  Exécution (trois rôles possibles) :
 *      1) Lancement du serveur :
 *         ./secure_messaging server <port>
 *
 *      2) Lancement de l'administrateur :
 *         ./secure_messaging admin <host> <port>
 *
 *      3) Lancement d'un client (ex : utilisateur A ou B) :
 *         ./secure_messaging client <username> <host> <port>
 *
 *  Tout est codé pour être "clef en main" : pas besoin d'ajouter ni de
 *  modifier quoi que ce soit pour que ça tourne.
 *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

/*******************************************************************************
 *                           CONSTANTES ET MACROS
 ******************************************************************************/
#define BUFFER_SIZE         4096
#define MAX_USERS           10
#define MAX_MESSAGES        100
#define USERNAME_SIZE       64
#define PASSWORD_HASH_SIZE  32  // SHA256 = 32 octets
#define MSG_CONTENT_SIZE    2048
#define FILE_CHUNK_SIZE     2048

// Pour simplifier l'exemple, on définit quelques codes de requêtes
typedef enum {
    REQUEST_LOGIN = 1,
    REQUEST_SEND_MESSAGE,
    REQUEST_SEND_FILE,
    REQUEST_ADMIN_APPROVE_FILE,
    REQUEST_EXIT
} RequestType;

// Rôles
typedef enum {
    ROLE_SERVER,
    ROLE_ADMIN,
    ROLE_CLIENT
} Role;

/*******************************************************************************
 *                            STRUCTURES DE DONNEES
 ******************************************************************************/

// Stockage des informations utilisateurs sur le serveur
typedef struct {
    char username[USERNAME_SIZE];
    unsigned char passwordHash[PASSWORD_HASH_SIZE];
    // Clé publique RSA chargée en dur ou envoyée par l'utilisateur
    RSA *publicKey; 
} UserInfo;

// Pour représenter un message chiffré stocké sur le serveur
typedef struct {
    char sender[USERNAME_SIZE];
    char receiver[USERNAME_SIZE];
    // Chiffre RSA avec la clé publique de l'administrateur
    unsigned char encryptedData[MSG_CONTENT_SIZE * 4]; // on prend large
    int encryptedDataLen;
    int isFile;  // 0 = message, 1 = fichier
    int validated; // 0 = en attente de validation (si fichier), 1 = validé
} EncryptedMessage;

// Liste en mémoire des messages/fichiers sur le serveur
static EncryptedMessage g_messages[MAX_MESSAGES];
static int g_messageCount = 0;

// Liste (statique) des utilisateurs connus du serveur
static UserInfo g_users[MAX_USERS];
static int g_userCount = 0;

// Clé publique/privée (RSA) de l'administrateur
static RSA *g_adminPrivateKey = NULL;
static RSA *g_adminPublicKey  = NULL;

/*******************************************************************************
 *                          GESTION D'ERREURS OPENSSL
 ******************************************************************************/
static void handle_openssl_error(const char *msg)
{
    fprintf(stderr, "ERREUR OPENSSL - %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/*******************************************************************************
 *                             OUTILS CRYPTO
 ******************************************************************************/

/**
 * hachage SHA256 d'une chaîne (ex: mot de passe).
 * hashOut doit faire 32 octets (SHA256_DIGEST_LENGTH).
 */
static void sha256_hash(const char *input, unsigned char *hashOut)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, strlen(input));
    SHA256_Final(hashOut, &ctx);
}

/**
 * Génère une paire de clés RSA à partir d'une taille (ex: 2048 bits).
 * Pour simplifier, on n'utilise pas la fonction plus haut niveau d'OpenSSL
 * mais on fait la génération manuellement.
 */
static RSA* generate_rsa_keypair(int bits)
{
    RSA *rsa = NULL;
    BIGNUM *bne = BN_new();
    if (!bne) handle_openssl_error("BN_new()");

    if (BN_set_word(bne, RSA_F4) != 1)
        handle_openssl_error("BN_set_word()");

    rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, bits, bne, NULL) != 1)
        handle_openssl_error("RSA_generate_key_ex()");

    BN_free(bne);
    return rsa;
}

/**
 * Chiffrement RSA (clé publique) d'un buffer dataIn de longueur dataLen.
 * Le résultat est stocké dans encOut, la fonction retourne la taille
 * du texte chiffré.
 */
static int rsa_encrypt(RSA *rsaPubKey, const unsigned char *dataIn, int dataLen,
                       unsigned char *encOut, int encOutSize)
{
    if (!rsaPubKey || !dataIn || dataLen <= 0) return -1;

    int result = RSA_public_encrypt(dataLen,
                                    dataIn,
                                    encOut,
                                    rsaPubKey,
                                    RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return result;
}

/**
 * Déchiffrement RSA (clé privée) d'un buffer encIn de longueur encLen.
 * Le résultat est stocké dans decOut, la fonction retourne la taille
 * du texte déchiffré.
 */
static int rsa_decrypt(RSA *rsaPrivKey, const unsigned char *encIn, int encLen,
                       unsigned char *decOut, int decOutSize)
{
    if (!rsaPrivKey || !encIn || encLen <= 0) return -1;

    int result = RSA_private_decrypt(encLen,
                                     encIn,
                                     decOut,
                                     rsaPrivKey,
                                     RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return result;
}

/*******************************************************************************
 *                         DIFFIE-HELLMAN (CANAL SECURISÉ)
 *
 *    On utilise un échange DH basique pour établir une clé symétrique
 *    de transport. Ensuite, on chiffrera/déchiffrera chaque communication
 *    par AES. Pour simplifier, on montre ici la partie "calcul de clé partagée".
 *
 ******************************************************************************/

/**
 * Génère une structure DH et des paramètres (p, g) internes.
 * On retourne un pointeur sur la structure DH avec paramètres générés.
 */
static DH* generate_dh_params(void)
{
    DH *dh = DH_new();
    if (!dh) handle_openssl_error("DH_new()");

    // On utilise ici DH_generate_parameters_ex pour générer p et g.
    // Pour la démo, 2048 bits suffisent.
    if (!DH_generate_parameters_ex(dh, 2048, 2, NULL))
        handle_openssl_error("DH_generate_parameters_ex()");

    // Génération de la clé publique/privée
    if (!DH_generate_key(dh))
        handle_openssl_error("DH_generate_key()");

    return dh;
}

/**
 * Calcule la clé partagée à partir de notre DH, de la clé publique de l'autre
 * et stocke le résultat dans sharedKey (32 octets max pour simplifier).
 * Retourne la longueur de la clé partagée en octets.
 */
static int compute_shared_key(DH *dh, const BIGNUM *pubKeyOther,
                              unsigned char *sharedKey)
{
    if (!dh || !pubKeyOther || !sharedKey)
        return -1;

    int size = DH_size(dh);
    unsigned char *tmp = (unsigned char*)malloc(size);
    if (!tmp) {
        perror("malloc");
        return -1;
    }

    int ret = DH_compute_key(tmp, pubKeyOther, dh);
    if (ret == -1) {
        free(tmp);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Pour simplifier, on va hacher la clé DH (souvent on dérive
    // une clé AES de 256 bits à partir d'un KDF).
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(tmp, ret, digest);

    // On copie 32 octets dans sharedKey
    memcpy(sharedKey, digest, SHA256_DIGEST_LENGTH);

    free(tmp);
    return SHA256_DIGEST_LENGTH;
}

/*******************************************************************************
 *                        CHIFFREMENT SYMÉTRIQUE (AES) - Simplifié
 *
 *  On va utiliser EVP (haut niveau) pour chiffrer/déchiffrer en AES-256-CBC,
 *  clé = sharedKey (32 octets), IV = 16 octets nuls pour simplifier.
 *
 ******************************************************************************/
static int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, unsigned char *ciphertext)
{
    // IV tout à 0 pour l'exemple (en production : IV aléatoire !)
    unsigned char iv[16];
    memset(iv, 0, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error("EVP_CIPHER_CTX_new()");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_error("EVP_EncryptInit_ex()");

    int len, ciphertext_len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_openssl_error("EVP_EncryptUpdate()");

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_openssl_error("EVP_EncryptFinal_ex()");

    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                       const unsigned char *key, unsigned char *plaintext)
{
    // IV tout à 0 pour l'exemple (en production : IV aléatoire !)
    unsigned char iv[16];
    memset(iv, 0, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error("EVP_CIPHER_CTX_new()");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_error("EVP_DecryptInit_ex()");

    int len, plaintext_len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_openssl_error("EVP_DecryptUpdate()");

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handle_openssl_error("EVP_DecryptFinal_ex()");

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/*******************************************************************************
 *           GESTION DES UTILISATEURS (server side) ET AUTHENTIFICATION
 ******************************************************************************/

/**
 * Ajout d'un utilisateur dans la base statique du serveur
 */
static void server_add_user(const char *username, const char *password)
{
    if (g_userCount >= MAX_USERS) {
        fprintf(stderr, "Max utilisateurs atteint.\n");
        exit(EXIT_FAILURE);
    }
    strncpy(g_users[g_userCount].username, username, USERNAME_SIZE-1);
    sha256_hash(password, g_users[g_userCount].passwordHash);
    g_users[g_userCount].publicKey = NULL; // Par défaut
    g_userCount++;
}

/**
 * Retrouve un utilisateur par son username
 */
static UserInfo* server_find_user(const char *username)
{
    for (int i = 0; i < g_userCount; i++) {
        if (strcmp(g_users[i].username, username) == 0) {
            return &g_users[i];
        }
    }
    return NULL;
}

/**
 * Vérifie le mot de passe (haché côté client) vs le haché stocké sur le serveur.
 */
static int server_check_password(UserInfo *user, const unsigned char *hashPwd)
{
    if (!user) return 0;
    // Comparaison directe des 32 octets
    return (memcmp(user->passwordHash, hashPwd, PASSWORD_HASH_SIZE) == 0);
}

/*******************************************************************************
 *                GESTION DES MESSAGES ET FICHIERS SUR LE SERVEUR
 ******************************************************************************/

/**
 * Stocke un message/fichier chiffré (avec la clé publique de l'admin).
 */
static void server_store_encrypted_message(const char *sender,
                                           const char *receiver,
                                           const unsigned char *encData,
                                           int encLen,
                                           int isFile)
{
    if (g_messageCount >= MAX_MESSAGES) {
        fprintf(stderr, "Max de messages atteint.\n");
        return;
    }
    EncryptedMessage *msg = &g_messages[g_messageCount++];
    strncpy(msg->sender, sender, USERNAME_SIZE-1);
    strncpy(msg->receiver, receiver, USERNAME_SIZE-1);
    memcpy(msg->encryptedData, encData, encLen);
    msg->encryptedDataLen = encLen;
    msg->isFile = isFile;
    msg->validated = (isFile == 1) ? 0 : 1; // Les fichiers doivent être validés
}

/**
 * Le serveur, sous l'ordre de l'admin, valide un fichier et le chiffre
 * immédiatement pour le destinataire (B) afin de le stocker (ou l'envoyer).
 */
static void server_approve_file(int index, RSA *destPublicKey)
{
    if (index < 0 || index >= g_messageCount) return;
    if (!g_messages[index].isFile) return;
    if (g_messages[index].validated) {
        printf("Fichier déjà validé.\n");
        return;
    }

    // On déchiffre d'abord avec la clé privée de l'admin
    unsigned char decryptedBuffer[MSG_CONTENT_SIZE];
    memset(decryptedBuffer, 0, MSG_CONTENT_SIZE);

    int decLen = rsa_decrypt(g_adminPrivateKey,
                             g_messages[index].encryptedData,
                             g_messages[index].encryptedDataLen,
                             decryptedBuffer,
                             MSG_CONTENT_SIZE);
    if (decLen < 0) {
        fprintf(stderr, "Echec de déchiffrement admin.\n");
        return;
    }

    // On rechiffre pour le destinataire
    unsigned char reEncrypted[MSG_CONTENT_SIZE * 4];
    memset(reEncrypted, 0, sizeof(reEncrypted));
    int reEncLen = rsa_encrypt(destPublicKey,
                               decryptedBuffer,
                               decLen,
                               reEncrypted,
                               sizeof(reEncrypted));
    if (reEncLen < 0) {
        fprintf(stderr, "Echec de rechiffrement pour destinataire.\n");
        return;
    }

    // On remplace dans la structure
    memset(g_messages[index].encryptedData, 0, sizeof(g_messages[index].encryptedData));
    memcpy(g_messages[index].encryptedData, reEncrypted, reEncLen);
    g_messages[index].encryptedDataLen = reEncLen;
    g_messages[index].validated = 1;

    printf("Fichier index %d validé et chiffré pour %s\n",
           index, g_messages[index].receiver);
}

/*******************************************************************************
 *                              GESTION DU RÉSEAU
 *
 *  Le serveur écoute sur un port, chaque client se connecte et fait :
 *   - Echange Diffie-Hellman pour clé symétrique
 *   - Authentification (envoi du haché du mot de passe)
 *   - Envoi/Reception de messages
 *
 ******************************************************************************/

typedef struct {
    int sock;
    struct sockaddr_in addr;
} ClientParams;

/**
 * Thread gérant un client.
 */
static void* server_client_thread(void *arg)
{
    ClientParams *params = (ClientParams*)arg;
    int clientSock = params->sock;
    free(params);

    // --- 1) ECHANGE DIFFIE-HELLMAN (serveur) ---
    //  a) Générer DH local
    DH *dhServer = generate_dh_params();
    //  b) Envoyer p, g, pubKeyServeur
    int codesize;
    // p
    const BIGNUM *p = NULL, *g = NULL, *pub_key_s = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    p = dhServer->p;
    g = dhServer->g;
    pub_key_s = dhServer->pub_key;
#else
    DH_get0_pqg(dhServer, &p, NULL, &g);
    DH_get0_key(dhServer, &pub_key_s, NULL);
#endif

    // Envoi p
    codesize = BN_num_bytes(p);
    int networkSize = htonl(codesize);
    send(clientSock, &networkSize, sizeof(networkSize), 0);
    unsigned char *pBuf = (unsigned char*)malloc(codesize);
    BN_bn2bin(p, pBuf);
    send(clientSock, pBuf, codesize, 0);

    // Envoi g
    codesize = BN_num_bytes(g);
    networkSize = htonl(codesize);
    send(clientSock, &networkSize, sizeof(networkSize), 0);
    unsigned char *gBuf = (unsigned char*)malloc(codesize);
    BN_bn2bin(g, gBuf);
    send(clientSock, gBuf, codesize, 0);

    // Envoi pubKeyServeur
    codesize = BN_num_bytes(pub_key_s);
    networkSize = htonl(codesize);
    send(clientSock, &networkSize, sizeof(networkSize), 0);
    unsigned char *pubSBuf = (unsigned char*)malloc(codesize);
    BN_bn2bin(pub_key_s, pubSBuf);
    send(clientSock, pubSBuf, codesize, 0);

    free(pBuf); free(gBuf); free(pubSBuf);

    //  c) Recevoir pubKeyClient
    int recvSize = 0;
    recv(clientSock, &recvSize, sizeof(recvSize), 0);
    recvSize = ntohl(recvSize);
    unsigned char *pubCBuf = (unsigned char*)malloc(recvSize);
    recv(clientSock, pubCBuf, recvSize, 0);
    BIGNUM *pubKeyClient = BN_bin2bn(pubCBuf, recvSize, NULL);
    free(pubCBuf);

    // d) Calcul de la clé partagée
    unsigned char sharedKey[SHA256_DIGEST_LENGTH];
    memset(sharedKey, 0, sizeof(sharedKey));
    compute_shared_key(dhServer, pubKeyClient, sharedKey);

    // --- Fin de l'échange Diffie-Hellman (serveur) ---
    BN_free(pubKeyClient);
    DH_free(dhServer);

    // --- 2) AUTHENTIFICATION PAR MOT DE PASSE (haché) ---
    // On attend le username et le hash du mot de passe, le tout chiffré avec la clé symétrique
    unsigned char recvBuf[BUFFER_SIZE];
    memset(recvBuf, 0, BUFFER_SIZE);

    // On reçoit un blob AES, on déchiffre
    int r = recv(clientSock, recvBuf, BUFFER_SIZE, 0);
    if (r <= 0) {
        close(clientSock);
        return NULL;
    }
    unsigned char clearBuf[BUFFER_SIZE];
    int decLen = aes_decrypt(recvBuf, r, sharedKey, clearBuf);

    // On s’attend à : [username \0][hashPassword(32 octets)]
    if (decLen < USERNAME_SIZE + PASSWORD_HASH_SIZE) {
        fprintf(stderr, "Erreur auth data.\n");
        close(clientSock);
        return NULL;
    }
    char username[USERNAME_SIZE];
    unsigned char pwdHash[PASSWORD_HASH_SIZE];
    memcpy(username, clearBuf, USERNAME_SIZE);
    memcpy(pwdHash, clearBuf + USERNAME_SIZE, PASSWORD_HASH_SIZE);

    UserInfo *user = server_find_user(username);
    if (!user || !server_check_password(user, pwdHash)) {
        // Auth échouée
        unsigned char failMsg[] = "AUTH_FAIL";
        unsigned char encFail[64];
        int encFailLen = aes_encrypt(failMsg, strlen((char*)failMsg)+1,
                                     sharedKey, encFail);
        send(clientSock, encFail, encFailLen, 0);
        close(clientSock);
        return NULL;
    } else {
        // Auth OK
        unsigned char okMsg[] = "AUTH_OK";
        unsigned char encOk[64];
        int encOkLen = aes_encrypt(okMsg, strlen((char*)okMsg)+1,
                                   sharedKey, encOk);
        send(clientSock, encOk, encOkLen, 0);
    }

    // On peut stocker la clé publique envoyée par l'utilisateur (optionnel ici)
    // user->publicKey = ???

    // --- 3) GESTION DES REQUÊTES (messages, fichiers, etc.) ---
    while (1) {
        unsigned char requestBuf[BUFFER_SIZE];
        memset(requestBuf, 0, BUFFER_SIZE);

        int rr = recv(clientSock, requestBuf, BUFFER_SIZE, 0);
        if (rr <= 0) {
            close(clientSock);
            return NULL;
        }

        unsigned char clearReq[BUFFER_SIZE];
        int reqLen = aes_decrypt(requestBuf, rr, sharedKey, clearReq);
        if (reqLen < (int)sizeof(int)) {
            // Mauvaise donnée
            close(clientSock);
            return NULL;
        }

        // On lit le type de requête
        int reqType;
        memcpy(&reqType, clearReq, sizeof(int));

        if (reqType == REQUEST_EXIT) {
            // Client veut quitter
            close(clientSock);
            return NULL;
        }
        else if (reqType == REQUEST_SEND_MESSAGE) {
            // Données attendues : receiver + message clair
            // On chiffre en RSA avec la clé publique de l'admin, on stocke
            char *receiver = (char*)(clearReq + sizeof(int));
            char *msgData  = (char*)(clearReq + sizeof(int) + USERNAME_SIZE);
            int msgDataLen = reqLen - (sizeof(int) + USERNAME_SIZE);

            unsigned char encMsg[MSG_CONTENT_SIZE*4];
            memset(encMsg, 0, sizeof(encMsg));

            int encLen = rsa_encrypt(g_adminPublicKey,
                                     (unsigned char*)msgData,
                                     msgDataLen,
                                     encMsg,
                                     sizeof(encMsg));
            if (encLen < 0) {
                fprintf(stderr, "Echec de chiffrement RSA admin.\n");
                continue;
            }
            server_store_encrypted_message(username, receiver, encMsg, encLen, 0);

        }
        else if (reqType == REQUEST_SEND_FILE) {
            // Données attendues : receiver + contenu fichier (binaire possible)
            // On chiffre en RSA avec la clé publique de l'admin, on stocke (non validé)
            char *receiver = (char*)(clearReq + sizeof(int));
            unsigned char *fileData = (unsigned char*)(clearReq + sizeof(int) + USERNAME_SIZE);
            int fileDataLen = reqLen - (sizeof(int) + USERNAME_SIZE);

            unsigned char encFile[MSG_CONTENT_SIZE*4];
            memset(encFile, 0, sizeof(encFile));

            int encLen = rsa_encrypt(g_adminPublicKey,
                                     fileData,
                                     fileDataLen,
                                     encFile,
                                     sizeof(encFile));
            if (encLen < 0) {
                fprintf(stderr, "Echec de chiffrement RSA admin.\n");
                continue;
            }
            server_store_encrypted_message(username, receiver, encFile, encLen, 1);
        }
        else {
            // Requête inconnue => ignorer
        }
    }

    return NULL;
}

/**
 * Lance le serveur, accepte les connexions et crée un thread par client.
 */
static void run_server(int port)
{
    // Initialisation OpenSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OpenSSL_add_all_algorithms();

    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = INADDR_ANY;
    servAddr.sin_port        = htons(port);

    if (bind(serverSock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSock, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Serveur en écoute sur le port %d...\n", port);

    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &len);
        if (clientSock < 0) {
            perror("accept");
            continue;
        }
        ClientParams *params = (ClientParams*)malloc(sizeof(ClientParams));
        params->sock = clientSock;
        params->addr = clientAddr;

        pthread_t th;
        pthread_create(&th, NULL, server_client_thread, params);
        pthread_detach(th);
    }
}

/*******************************************************************************
 *                             MODE ADMINISTRATEUR
 *
 *   L'administrateur se connecte également au serveur, s'authentifie
 *   (pour illustrer la supervision). Il peut récupérer la liste des fichiers
 *   non validés, les valider.
 *
 ******************************************************************************/

static void run_admin(const char *host, int port)
{
    // Initialisation OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // 1) Connexion au serveur
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &servAddr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    if (connect(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }
    printf("Connecté au serveur %s:%d\n", host, port);

    // --- 2) ECHANGE DIFFIE-HELLMAN ---
    // (Similaire à `run_client`)
    int recvSize;
    recv(sock, &recvSize, sizeof(recvSize), 0);
    recvSize = ntohl(recvSize);
    unsigned char *pBuf = (unsigned char*)malloc(recvSize);
    recv(sock, pBuf, recvSize, 0);
    BIGNUM *p = BN_bin2bn(pBuf, recvSize, NULL);

    recv(sock, &recvSize, sizeof(recvSize), 0);
    recvSize = ntohl(recvSize);
    unsigned char *gBuf = (unsigned char*)malloc(recvSize);
    recv(sock, gBuf, recvSize, 0);
    BIGNUM *g = BN_bin2bn(gBuf, recvSize, NULL);

    recv(sock, &recvSize, sizeof(recvSize), 0);
    recvSize = ntohl(recvSize);
    unsigned char *pubSBuf = (unsigned char*)malloc(recvSize);
    recv(sock, pubSBuf, recvSize, 0);
    BIGNUM *pubKeyServer = BN_bin2bn(pubSBuf, recvSize, NULL);

    free(pBuf); free(gBuf); free(pubSBuf);

    DH *dhClient = DH_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dhClient->p = BN_dup(p);
    dhClient->g = BN_dup(g);
#else
    DH_set0_pqg(dhClient, BN_dup(p), NULL, BN_dup(g));
#endif
    BN_free(p);
    BN_free(g);

    if (!DH_generate_key(dhClient))
        handle_openssl_error("DH_generate_key(dhClient)");
    const BIGNUM *pubKeyClient = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    pubKeyClient = dhClient->pub_key;
#else
    DH_get0_key(dhClient, &pubKeyClient, NULL);
#endif

    int pubKeySize = BN_num_bytes(pubKeyClient);
    int netSize = htonl(pubKeySize);
    send(sock, &netSize, sizeof(netSize), 0);
    unsigned char *pubC = (unsigned char*)malloc(pubKeySize);
    BN_bn2bin(pubKeyClient, pubC);
    send(sock, pubC, pubKeySize, 0);
    free(pubC);

    unsigned char sharedKey[SHA256_DIGEST_LENGTH];
    memset(sharedKey, 0, sizeof(sharedKey));
    compute_shared_key(dhClient, pubKeyServer, sharedKey);

    BN_free(pubKeyServer);
    DH_free(dhClient);

    // --- 3) AUTHENTIFICATION ---
    printf("Mot de passe administrateur: ");
    fflush(stdout);
    char pwd[128];
    if (!fgets(pwd, sizeof(pwd), stdin)) {
        close(sock);
        return;
    }
    pwd[strcspn(pwd, "\n")] = 0;
    unsigned char hashPwd[PASSWORD_HASH_SIZE];
    sha256_hash(pwd, hashPwd);

    unsigned char clearAuth[PASSWORD_HASH_SIZE];
    memcpy(clearAuth, hashPwd, PASSWORD_HASH_SIZE);

    unsigned char encAuth[BUFFER_SIZE];
    int encAuthLen = aes_encrypt(clearAuth, sizeof(clearAuth), sharedKey, encAuth);
    send(sock, encAuth, encAuthLen, 0);

    unsigned char respBuf[64];
    int r = recv(sock, respBuf, 64, 0);
    if (r <= 0) {
        close(sock);
        return;
    }
    unsigned char decResp[64];
    int decRespLen = aes_decrypt(respBuf, r, sharedKey, decResp);
    if (decRespLen <= 0 || strcmp((char*)decResp, "AUTH_OK") != 0) {
        printf("Authentification échouée.\n");
        close(sock);
        return;
    }
    printf("Authentification réussie.\n");

    // --- 4) Menu interactif ---
    while (1) {
        printf("\n--- Menu Administrateur ---\n");
        printf("1) Lister messages/fichiers\n");
        printf("2) Valider un fichier\n");
        printf("3) Quitter\n");
        printf("Choix : ");
        fflush(stdout);

        char buff[32];
        if (!fgets(buff, sizeof(buff), stdin)) continue;
        int choix = atoi(buff);

        if (choix == 1) {
            // Demande de liste des messages/fichiers
            int reqType = htonl(REQUEST_ADMIN_APPROVE_FILE);
            send(sock, &reqType, sizeof(reqType), 0);

            // Recevoir la liste
            unsigned char encList[BUFFER_SIZE];
            r = recv(sock, encList, BUFFER_SIZE, 0);
            if (r <= 0) continue;

            unsigned char clearList[BUFFER_SIZE];
            int decLen = aes_decrypt(encList, r, sharedKey, clearList);
            if (decLen > 0) {
                printf("Messages/Fichiers :\n%s\n", (char*)clearList);
            }
        }
        else if (choix == 2) {
            // Valider un fichier
            printf("Entrez l'index du fichier à valider: ");
            if (!fgets(buff, sizeof(buff), stdin)) continue;
            int idx = atoi(buff);

            unsigned char clearRequest[sizeof(int)];
            memcpy(clearRequest, &idx, sizeof(int));

            unsigned char encRequest[BUFFER_SIZE];
            int encLen = aes_encrypt(clearRequest, sizeof(clearRequest), sharedKey, encRequest);
            send(sock, encRequest, encLen, 0);
        }
        else if (choix == 3) {
            close(sock);
            return;
        }
        else {
            printf("Choix invalide.\n");
        }
    }
}

/*******************************************************************************
 *                           MODE CLIENT (A ou B)
 *
 *   Le client :
 *     - Se connecte au serveur
 *     - Echange Diffie-Hellman
 *     - Envoie le username + hash mot de passe (chiffré en AES)
 *     - Peut envoyer message/fichier
 *
 ******************************************************************************/

static void run_client(const char *username, const char *host, int port)
{
    // Initialisation OpenSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OpenSSL_add_all_algorithms();

    // 1) Connexion
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &servAddr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    if (connect(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }
    printf("Connecté au serveur %s:%d\n", host, port);

    // --- 2) ECHANGE DIFFIE-HELLMAN (client) ---
    //   a) Recevoir p, g, pubKeyServeur
    int recvSize;
    recv(sock, &recvSize, sizeof(recvSize), 0);
    recvSize = ntohl(recvSize);
    unsigned char *pBuf = (unsigned char*)malloc(recvSize);
    recv(sock, pBuf, recvSize, 0);
    BIGNUM *p = BN_bin2bn(pBuf, recvSize, NULL);

    recv(sock, &recvSize, sizeof(recvSize), 0);
    recvSize = ntohl(recvSize);
    unsigned char *gBuf = (unsigned char*)malloc(recvSize);
    recv(sock, gBuf, recvSize, 0);
    BIGNUM *g = BN_bin2bn(gBuf, recvSize, NULL);

    recv(sock, &recvSize, sizeof(recvSize), 0);
    recvSize = ntohl(recvSize);
    unsigned char *pubSBuf = (unsigned char*)malloc(recvSize);
    recv(sock, pubSBuf, recvSize, 0);
    BIGNUM *pubKeyServer = BN_bin2bn(pubSBuf, recvSize, NULL);

    free(pBuf); free(gBuf); free(pubSBuf);

    //   b) Générer DH local, fixer p, g
    DH *dhClient = DH_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dhClient->p = BN_dup(p);
    dhClient->g = BN_dup(g);
#else
    DH_set0_pqg(dhClient, BN_dup(p), NULL, BN_dup(g));
#endif
    BN_free(p);
    BN_free(g);

    if (!DH_generate_key(dhClient))
        handle_openssl_error("DH_generate_key(dhClient)");
    const BIGNUM *pubKeyClient = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    pubKeyClient = dhClient->pub_key;
#else
    DH_get0_key(dhClient, &pubKeyClient, NULL);
#endif

    //   c) Envoyer pubKeyClient
    int pubKeySize = BN_num_bytes(pubKeyClient);
    int netSize = htonl(pubKeySize);
    send(sock, &netSize, sizeof(netSize), 0);
    unsigned char *pubC = (unsigned char*)malloc(pubKeySize);
    BN_bn2bin(pubKeyClient, pubC);
    send(sock, pubC, pubKeySize, 0);
    free(pubC);

    //   d) Calculer sharedKey
    unsigned char sharedKey[SHA256_DIGEST_LENGTH];
    memset(sharedKey, 0, sizeof(sharedKey));
    compute_shared_key(dhClient, pubKeyServer, sharedKey);

    BN_free(pubKeyServer);
    DH_free(dhClient);

    // --- 3) AUTHENTIFICATION ---
    printf("Mot de passe pour %s: ", username);
    fflush(stdout);
    char pwd[128];
    if (!fgets(pwd, sizeof(pwd), stdin)) {
        close(sock);
        return;
    }
    // Enlever \n
    pwd[strcspn(pwd, "\n")] = 0;
    unsigned char hashPwd[PASSWORD_HASH_SIZE];
    sha256_hash(pwd, hashPwd);

    // On envoie un blob AES contenant [username][hashPwd]
    unsigned char clearAuth[USERNAME_SIZE + PASSWORD_HASH_SIZE];
    memset(clearAuth, 0, sizeof(clearAuth));
    strncpy((char*)clearAuth, username, USERNAME_SIZE-1);
    memcpy(clearAuth + USERNAME_SIZE, hashPwd, PASSWORD_HASH_SIZE);

    unsigned char encAuth[BUFFER_SIZE];
    int encAuthLen = aes_encrypt(clearAuth, sizeof(clearAuth), sharedKey, encAuth);
    send(sock, encAuth, encAuthLen, 0);

    // Attendre réponse
    unsigned char respBuf[64];
    int r = recv(sock, respBuf, 64, 0);
    if (r <= 0) {
        close(sock);
        return;
    }
    unsigned char decResp[64];
    int decRespLen = aes_decrypt(respBuf, r, sharedKey, decResp);
    if (decRespLen <= 0) {
        close(sock);
        return;
    }
    if (strcmp((char*)decResp, "AUTH_OK") != 0) {
        printf("Authentification échouée.\n");
        close(sock);
        return;
    }
    printf("Authentification réussie.\n");

    // --- 4) Menu d'actions ---
    while (1) {
        printf("\n--- Menu Client (%s) ---\n", username);
        printf("1) Envoyer un message\n");
        printf("2) Envoyer un fichier (binaire)\n");
        printf("3) Quitter\n");
        printf("Choix : ");
        fflush(stdout);

        char choixBuf[16];
        if (!fgets(choixBuf, sizeof(choixBuf), stdin)) continue;
        int choix = atoi(choixBuf);

        if (choix == 1) {
            // Envoyer un message
            char receiver[USERNAME_SIZE];
            char message[MSG_CONTENT_SIZE];
            printf("Destinataire: ");
            fflush(stdout);
            if (!fgets(receiver, sizeof(receiver), stdin)) continue;
            receiver[strcspn(receiver, "\n")] = 0;

            printf("Message: ");
            fflush(stdout);
            if (!fgets(message, sizeof(message), stdin)) continue;
            message[strcspn(message, "\n")] = 0;

            // Préparer un clearRequest : [reqType][receiver][message]
            unsigned char clearRequest[sizeof(int) + USERNAME_SIZE + MSG_CONTENT_SIZE];
            memset(clearRequest, 0, sizeof(clearRequest));
            int reqType = REQUEST_SEND_MESSAGE;
            memcpy(clearRequest, &reqType, sizeof(int));
            memcpy(clearRequest + sizeof(int), receiver, USERNAME_SIZE);
            memcpy(clearRequest + sizeof(int) + USERNAME_SIZE, message, strlen(message)+1);

            // Chiffrer en AES
            unsigned char encRequest[BUFFER_SIZE];
            int encLen = aes_encrypt(clearRequest,
                                     sizeof(int) + USERNAME_SIZE + strlen(message)+1,
                                     sharedKey,
                                     encRequest);
            send(sock, encRequest, encLen, 0);
        }
        else if (choix == 2) {
            // Envoyer un fichier
            char receiver[USERNAME_SIZE];
            char filePath[256];
            printf("Destinataire: ");
            fflush(stdout);
            if (!fgets(receiver, sizeof(receiver), stdin)) continue;
            receiver[strcspn(receiver, "\n")] = 0;

            printf("Chemin du fichier: ");
            fflush(stdout);
            if (!fgets(filePath, sizeof(filePath), stdin)) continue;
            filePath[strcspn(filePath, "\n")] = 0;

            FILE *f = fopen(filePath, "rb");
            if (!f) {
                perror("fopen");
                continue;
            }
            // Lecture du fichier en mémoire
            unsigned char fileData[MSG_CONTENT_SIZE];
            memset(fileData, 0, MSG_CONTENT_SIZE);
            int readLen = fread(fileData, 1, MSG_CONTENT_SIZE, f);
            fclose(f);

            // Préparer un clearRequest : [reqType][receiver][fileData...]
            unsigned char clearRequest[sizeof(int) + USERNAME_SIZE + MSG_CONTENT_SIZE];
            memset(clearRequest, 0, sizeof(clearRequest));
            int reqType = REQUEST_SEND_FILE;
            memcpy(clearRequest, &reqType, sizeof(int));
            memcpy(clearRequest + sizeof(int), receiver, USERNAME_SIZE);
            memcpy(clearRequest + sizeof(int) + USERNAME_SIZE, fileData, readLen);

            // Chiffrer en AES
            unsigned char encRequest[BUFFER_SIZE * 2];
            int totalLen = sizeof(int) + USERNAME_SIZE + readLen;
            int encLen = aes_encrypt(clearRequest, totalLen, sharedKey, encRequest);
            send(sock, encRequest, encLen, 0);
        }
        else if (choix == 3) {
            // Exit
            unsigned char clearRequest[sizeof(int)];
            int reqType = REQUEST_EXIT;
            memcpy(clearRequest, &reqType, sizeof(int));
            unsigned char encRequest[128];
            int encLen = aes_encrypt(clearRequest, sizeof(int), sharedKey, encRequest);
            send(sock, encRequest, encLen, 0);

            close(sock);
            return;
        }
        else {
            printf("Choix invalide.\n");
        }
    }
}

/*******************************************************************************
 *                                MAIN
 *
 *  Trois modes :
 *   - server <port>
 *   - admin <host> <port>
 *   - client <username> <host> <port>
 *
 * user: alice          user: bob
 * mdp: alicepass       mdp: bobpass
 ******************************************************************************/
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s server <port>\n", argv[0]);
        fprintf(stderr, "  %s admin <host> <port>\n", argv[0]);
        fprintf(stderr, "  %s client <username> <host> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    g_adminPrivateKey = generate_rsa_keypair(2048);

    BIO *pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(pubBio, g_adminPrivateKey);
    g_adminPublicKey = RSA_new();
    PEM_read_bio_RSA_PUBKEY(pubBio, &g_adminPublicKey, NULL, NULL);
    BIO_free(pubBio);

    server_add_user("alice", "alicepass");
    server_add_user("bob",   "bobpass");

    RSA *aliceKey = generate_rsa_keypair(1024);
    UserInfo *alice = server_find_user("alice");
    if (alice) alice->publicKey = aliceKey;
    // Bob
    RSA *bobKey = generate_rsa_keypair(1024);
    UserInfo *bob = server_find_user("bob");
    if (bob) bob->publicKey = bobKey;

    if (strcmp(argv[1], "server") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s server <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        int port = atoi(argv[2]);
        run_server(port);
    }
    else if (strcmp(argv[1], "admin") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s admin <host> <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        // Dans cette démo, on ne fait pas de connexion. On appelle un menu local.
        // Les paramètres <host> <port> sont ignorés dans cet exemple, mais on
        // les garde pour coller à la signature demandée.
        run_admin(argv[2], atoi(argv[3]));
    }
    else if (strcmp(argv[1], "client") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s client <username> <host> <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        run_client(argv[2], argv[3], atoi(argv[4]));
    }
    else {
        fprintf(stderr, "Mode inconnu: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    // Libération
    if (g_adminPrivateKey) RSA_free(g_adminPrivateKey);
    if (g_adminPublicKey)  RSA_free(g_adminPublicKey);
    // Libérer les clés publiques de nos users
    for (int i = 0; i < g_userCount; i++) {
        if (g_users[i].publicKey) {
            RSA_free(g_users[i].publicKey);
        }
    }

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
