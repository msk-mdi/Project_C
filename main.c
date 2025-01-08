#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* --------------------------------------------------------------------
 * Structures de données
 * ------------------------------------------------------------------*/

/**
 * Structure décrivant une session Diffie-Hellman.
 * Elle contient la clé DH, la clé partagée (après DH), ainsi que la taille de la clé.
 */
typedef struct {
    DH      *dh;
    unsigned char *shared_key;
    int            shared_key_size;
} DiffieHellmanSession;

/**
 * Structure décrivant l'utilisateur courant (côté serveur ou client)
 * - username: nom d'utilisateur
 * - public_key, private_key: clés RSA (si besoin côté serveur, par ex. pour l'administrateur)
 */
typedef struct {
    char      username[64];
    RSA      *public_key;
    RSA      *private_key;
} User;

/**
 * Structure pour représenter le "serveur" qui orchestre les échanges
 * - admin_key_pub, admin_key_priv : clés publiques/privées de l’administrateur
 * - (Optionnel) base de données des utilisateurs, sessions actives, etc.
 */
typedef struct {
    RSA *admin_key_pub;
    RSA *admin_key_priv;
    // ... potentiellement d'autres champs (listes de sessions, sockets, etc.)
} Server;

/* --------------------------------------------------------------------
 * Fonctions utilitaires (gestion des erreurs OpenSSL, etc.)
 * ------------------------------------------------------------------*/
static void handle_openssl_error(const char *msg)
{
    fprintf(stderr, "[ERREUR] %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/* --------------------------------------------------------------------
 * Fonctions pour la gestion du hachage (authentification du mot de passe)
 * ------------------------------------------------------------------*/

/**
 * Calcule un haché SHA256 du mot de passe (avec un éventuel salt).
 * Dans un code de production, on utiliserait PBKDF2, Argon2, bcrypt, etc.
 */
static void compute_password_hash(const char *password, unsigned char *output_hash)
{
    // Exemple simplifié : SHA256 direct
    // En production, ajouter un salt, un nombre d’itérations, etc.
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, password, strlen(password));
    SHA256_Final(output_hash, &sha_ctx);
}

/**
 * Vérifie si le haché calculé correspond à un haché stocké (authentification).
 * Dans un vrai système, on comparerait un haché stocké en base pour l'utilisateur.
 */
static int verify_password_hash(const char *password, const unsigned char *reference_hash)
{
    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
    compute_password_hash(password, computed_hash);
    // Compare les deux tableaux
    return (memcmp(computed_hash, reference_hash, SHA256_DIGEST_LENGTH) == 0);
}

/* --------------------------------------------------------------------
 * Fonctions de configuration Diffie-Hellman
 * ------------------------------------------------------------------*/

/**
 * Initialise une session Diffie-Hellman (génération de paramètres et de clés)
 */
DiffieHellmanSession* dh_init_session(void)
{
    DiffieHellmanSession *session = calloc(1, sizeof(DiffieHellmanSession));
    if(!session) {
        fprintf(stderr, "[ERREUR] Allocation mémoire pour session DH\n");
        return NULL;
    }

    session->dh = DH_new();
    if(!session->dh) {
        free(session);
        handle_openssl_error("Échec de DH_new");
    }

    /* Génération de paramètres sûrs (génération P, G).  
       En production, on utilise souvent des paramètres connus ou un code de génération sûr. */
    if(!DH_generate_parameters_ex(session->dh, 2048, DH_GENERATOR_2, NULL)) {
        DH_free(session->dh);
        free(session);
        handle_openssl_error("Échec de DH_generate_parameters_ex");
    }

    /* Génère la clé privée/publique pour cette session */
    if(!DH_generate_key(session->dh)) {
        DH_free(session->dh);
        free(session);
        handle_openssl_error("Échec de DH_generate_key");
    }

    return session;
}

/**
 * Calcule la clé partagée après échange de la clé publique du pair
 * (public_key_peer est la clé publique reçue de l'autre partie)
 */
int dh_compute_shared_key(DiffieHellmanSession *session, const BIGNUM *public_key_peer)
{
    if(!session || !session->dh || !public_key_peer) {
        return 0;
    }

    int key_size = DH_size(session->dh);
    session->shared_key = calloc(1, key_size);
    if(!session->shared_key) {
        fprintf(stderr, "[ERREUR] Allocation mémoire shared_key\n");
        return 0;
    }

    int ret = DH_compute_key(session->shared_key, public_key_peer, session->dh);
    if(ret < 0) {
        free(session->shared_key);
        session->shared_key = NULL;
        handle_openssl_error("Échec de DH_compute_key");
    }
    session->shared_key_size = ret;
    return 1;
}

/* --------------------------------------------------------------------
 * Fonctions de chiffrement symétrique (AES) sur la clé partagée
 * ------------------------------------------------------------------*/

/**
 * Exemple basique pour chiffrer en AES-256-CBC avec la clé partagée (session->shared_key).
 * - in, in_len : données en clair
 * - out : buffer de sortie chiffré
 * - out_len : taille produite
 */
static int aes_encrypt(const unsigned char *in, int in_len,
                       unsigned char *out, int *out_len,
                       const unsigned char *key, int key_len)
{
    // Pour un usage production, gérer IV de façon appropriée (aléatoire).
    // Ici on le met à zéro pour simplifier (exemple !).
    unsigned char iv[16] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) handle_openssl_error("Échec de EVP_CIPHER_CTX_new");

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_error("EVP_EncryptInit_ex");

    int len = 0, ciphertext_len = 0;
    if(1 != EVP_EncryptUpdate(ctx, out, &len, in, in_len))
        handle_openssl_error("EVP_EncryptUpdate");
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, out + len, &len))
        handle_openssl_error("EVP_EncryptFinal_ex");
    ciphertext_len += len;

    *out_len = ciphertext_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

/**
 * Même logique pour déchiffrer en AES-256-CBC
 */
static int aes_decrypt(const unsigned char *in, int in_len,
                       unsigned char *out, int *out_len,
                       const unsigned char *key, int key_len)
{
    unsigned char iv[16] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) handle_openssl_error("Échec de EVP_CIPHER_CTX_new");

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_error("EVP_DecryptInit_ex");

    int len = 0, plaintext_len = 0;
    if(1 != EVP_DecryptUpdate(ctx, out, &len, in, in_len))
        handle_openssl_error("EVP_DecryptUpdate");
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, out + len, &len))
        handle_openssl_error("EVP_DecryptFinal_ex");
    plaintext_len += len;

    *out_len = plaintext_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

/* --------------------------------------------------------------------
 * Fonctions de chiffrement RSA (pour l'administrateur et/ou utilisateurs)
 * ------------------------------------------------------------------*/

static int rsa_encrypt_with_public_key(const unsigned char *in, int in_len,
                                       unsigned char *out, RSA *rsa_pub)
{
    if(!rsa_pub) {
        fprintf(stderr, "[ERREUR] rsa_pub NULL\n");
        return -1;
    }

    int rsa_size = RSA_size(rsa_pub);
    // RSA_PKCS1_OAEP_PADDING recommandé, ou RSA_PKCS1_PADDING, etc.
    int len = RSA_public_encrypt(in_len, in, out, rsa_pub, RSA_PKCS1_OAEP_PADDING);
    if(len == -1) {
        handle_openssl_error("Échec RSA_public_encrypt");
    }
    return len; // Taille des données chiffrées
}

static int rsa_decrypt_with_private_key(const unsigned char *in, int in_len,
                                        unsigned char *out, RSA *rsa_priv)
{
    if(!rsa_priv) {
        fprintf(stderr, "[ERREUR] rsa_priv NULL\n");
        return -1;
    }
    int len = RSA_private_decrypt(in_len, in, out, rsa_priv, RSA_PKCS1_OAEP_PADDING);
    if(len == -1) {
        handle_openssl_error("Échec RSA_private_decrypt");
    }
    return len;
}

/* --------------------------------------------------------------------
 * Gestion des messages : envoi A -> Serveur -> (admin) -> B
 * ------------------------------------------------------------------*/

/**
 * Fonctions pour illustrer le workflow:
 * 1) A envoie le message chiffré en AES (clé partagée) au serveur.
 * 2) Le serveur déchiffre via la clé partagée, puis chiffre avec la clé publique de l’admin (RSA) pour stockage/lecture.
 * 3) L’administrateur (via sa clé privée) lit le message.
 * 4) (Si validé) le serveur re-chiffre le message avec la clé publique de B, puis l’envoie à B.
 * 5) B le déchiffre avec sa clé privée.
 */

/* Fait partie du code serveur, qui reçoit le message d’A */
static int server_receive_message(Server *srv,
                                  DiffieHellmanSession *sessionA,
                                  const unsigned char *encrypted_msg_from_A,
                                  int encrypted_len_from_A,
                                  unsigned char **rsa_encrypted_for_admin,
                                  int *rsa_len_for_admin)
{
    // 1) Déchiffrer le message AES (clé partagée A-Serveur)
    unsigned char plaintext[4096];
    int plain_len = 0;
    if(!aes_decrypt(encrypted_msg_from_A, encrypted_len_from_A,
                    plaintext, &plain_len,
                    sessionA->shared_key, sessionA->shared_key_size))
    {
        fprintf(stderr, "[ERREUR] aes_decrypt\n");
        return 0;
    }

    // 2) Chiffrer le message avec la clé publique de l’admin
    //    pour que l’admin puisse le lire. On stocke ce ciphertext RSA.
    int rsa_size = RSA_size(srv->admin_key_pub);
    *rsa_encrypted_for_admin = calloc(1, rsa_size);
    if(!(*rsa_encrypted_for_admin)) {
        fprintf(stderr, "[ERREUR] Allocation\n");
        return 0;
    }

    int ret = rsa_encrypt_with_public_key(
        plaintext, plain_len, *rsa_encrypted_for_admin, srv->admin_key_pub);
    if(ret == -1) {
        free(*rsa_encrypted_for_admin);
        return 0;
    }
    *rsa_len_for_admin = ret;
    return 1;
}

/* L’administrateur lit le message (chiffrement RSA) */
static int admin_read_message(Server *srv,
                              const unsigned char *rsa_encrypted_msg,
                              int rsa_encrypted_len,
                              unsigned char *out_plain, int *out_len)
{
    // 1) Déchiffre avec la clé privée de l’admin
    int dec_len = rsa_decrypt_with_private_key(
        rsa_encrypted_msg, rsa_encrypted_len, out_plain, srv->admin_key_priv);
    if(dec_len == -1) return 0;

    *out_len = dec_len;
    return 1;
}

/* Une fois validé, le serveur re-chiffre pour l’utilisateur B */
static int server_forward_message_to_B(Server *srv, 
                                       const unsigned char *plaintext,
                                       int plaintext_len,
                                       RSA *b_public_key,
                                       unsigned char **out_for_b,
                                       int *out_for_b_len)
{
    // 1) Chiffrer en RSA avec la clé publique de B
    int rsa_size = RSA_size(b_public_key);
    *out_for_b = calloc(1, rsa_size);
    if(!(*out_for_b)) return 0;

    int ret = rsa_encrypt_with_public_key(
        plaintext, plaintext_len, *out_for_b, b_public_key);
    if(ret == -1) {
        free(*out_for_b);
        return 0;
    }
    *out_for_b_len = ret;
    return 1;
}

/* --------------------------------------------------------------------
 * Même idée pour la validation des fichiers par l’administrateur
 * 1) Fichier envoyé A -> Serveur en AES
 * 2) Serveur -> chiffrement RSA admin
 * 3) Admin déchiffre, lit, valide
 * 4) Serveur rechiffre en RSA -> B
 * 5) Envoi B en AES
 * ------------------------------------------------------------------*/

/* --------------------------------------------------------------------
 * Extrait d'une fonction principale (main) illustrant le flux.
 * ------------------------------------------------------------------*/

int main(void)
{
    /* Initialisation OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Chargement/initialisation des clés de l'admin (on suppose que vous avez déjà
       généré admin_key_pub.pem et admin_key_priv.pem, par exemple via openssl). */
    FILE *fpub = fopen("admin_key_pub.pem", "r");
    FILE *fpriv = fopen("admin_key_priv.pem", "r");
    if(!fpub || !fpriv) {
        fprintf(stderr, "[ERREUR] Impossible d'ouvrir les clés admin\n");
        return EXIT_FAILURE;
    }

    RSA *admin_pub_key = PEM_read_RSA_PUBKEY(fpub, NULL, NULL, NULL);
    RSA *admin_priv_key = PEM_read_RSAPrivateKey(fpriv, NULL, NULL, NULL);
    fclose(fpub);
    fclose(fpriv);
    if(!admin_pub_key || !admin_priv_key) {
        handle_openssl_error("Lecture des clés Admin");
    }

    /* Initialisation du serveur */
    Server server;
    memset(&server, 0, sizeof(server));
    server.admin_key_pub  = admin_pub_key;
    server.admin_key_priv = admin_priv_key;

    /* EXEMPLE : Simulation d’un échange A -> Serveur -> Admin -> B */
    // 1) Ouverture d’une session Diffie-Hellman côté Serveur pour l’utilisateur A
    DiffieHellmanSession *sessionA = dh_init_session();
    // (En pratique, on enverrait sessionA->dh->pub_key à A, 
    //  on recevrait la pub_key de A pour calculer la clé partagée).
    // ICI, c’est un exemple simplifié ; on suppose qu’on a la clé publique de A.
    // ...
    // sessionA->shared_key = ... // calculé après réception pubkey de A

    // 2) L’utilisateur A a envoyé un message en AES avec la clé partagée sessionA->shared_key
    // On simule un "encrypted_msg_from_A" (chiffré AES).
    // On va directement chiffrer "Hello, ce message doit être supervisé" comme si c’était A.
    unsigned char original_msg[] = "Hello, ce message doit être supervisé";
    unsigned char aes_cipher[1024];
    int aes_cipher_len = 0;

    // On chiffre localement (imitant l'utilisateur A).
    aes_encrypt(original_msg, (int)strlen((char*)original_msg),
                aes_cipher, &aes_cipher_len,
                /* suppose qu’on a la shared_key A-Serveur */(unsigned char*)"01234567890123456789012345678901",
                32 /* 256 bits */);

    // 3) Serveur reçoit le message, le déchiffre, le chiffre pour l’admin.
    unsigned char *rsa_encrypted_for_admin = NULL;
    int rsa_len_for_admin = 0;
    server_receive_message(&server,
                           sessionA,
                           aes_cipher, aes_cipher_len,
                           &rsa_encrypted_for_admin,
                           &rsa_len_for_admin);

    // 4) L’administrateur lit le message (RSA decrypt).
    unsigned char admin_plain[4096];
    int admin_plain_len = 0;
    admin_read_message(&server,
                       rsa_encrypted_for_admin, rsa_len_for_admin,
                       admin_plain, &admin_plain_len);
    admin_plain[admin_plain_len] = '\0';
    printf("[ADMIN] Message reçu et déchiffré: %s\n", admin_plain);

    // 5) Suppose que l’admin valide. On re-chiffre pour B (via la clé publique de B).
    //    On suppose qu’on a déjà la clé publique de B (b_pub_key).
    FILE *fBpub = fopen("b_key_pub.pem", "r"); // par ex.
    if(!fBpub) {
        fprintf(stderr, "[ERREUR] Impossible d'ouvrir la clé publique de B\n");
        // Nettoyage mémoire
        free(rsa_encrypted_for_admin);
        DH_free(sessionA->dh);
        free(sessionA->shared_key);
        free(sessionA);
        RSA_free(admin_pub_key);
        RSA_free(admin_priv_key);
        return EXIT_FAILURE;
    }

    RSA *b_pub_key = PEM_read_RSA_PUBKEY(fBpub, NULL, NULL, NULL);
    fclose(fBpub);
    if(!b_pub_key) {
        handle_openssl_error("Lecture de la clé publique de B");
    }

    unsigned char *rsa_for_b = NULL;
    int rsa_for_b_len = 0;
    server_forward_message_to_B(&server,
                                admin_plain, admin_plain_len,
                                b_pub_key,
                                &rsa_for_b, &rsa_for_b_len);

    printf("[SERVEUR] Message re-chiffré pour B en RSA (taille %d octets)\n", rsa_for_b_len);

    // (ensuite on enverrait rsa_for_b via un canal sécurisé (DH) vers B qui le déchiffrerait)

    /* Nettoyages de fin */
    free(rsa_encrypted_for_admin);
    free(rsa_for_b);
    RSA_free(b_pub_key);
    DH_free(sessionA->dh);
    free(sessionA->shared_key);
    free(sessionA);
    RSA_free(admin_pub_key);
    RSA_free(admin_priv_key);

    return EXIT_SUCCESS;
}
