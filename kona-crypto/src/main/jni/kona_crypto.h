/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto */

#ifndef _Included_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
#define _Included_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
#ifdef __cplusplus
extern "C" {
#endif
#undef com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_GOOD
#define com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_GOOD 0L
#undef com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_BAD
#define com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_BAD -1L
/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3CreateCtx
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3CreateCtx
  (JNIEnv *, jobject);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3FreeCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3FreeCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3Update
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Update
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3Final
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Final
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3Reset
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Reset
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3Clone
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Clone
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3hmacCreateCtx
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacCreateCtx
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3hmacFreeCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacFreeCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3hmacUpdate
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacUpdate
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3hmacFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacFinal
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3hmacReset
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacReset
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm3hmacClone
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacClone
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm4CreateCtx
 * Signature: (ZLjava/lang/String;Z[B[B)J
 */
JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4CreateCtx
  (JNIEnv *, jobject, jboolean, jstring, jboolean, jbyteArray, jbyteArray);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm4FreeCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4FreeCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm4Update
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4Update
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm4Final
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4Final
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm4GCMUpdateAAD
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4GCMUpdateAAD
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm4GCMProcTag
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4GCMProcTag
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm2CreateCtx
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2CreateCtx
  (JNIEnv *, jobject);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm2FreeCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2FreeCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto
 * Method:    sm2GenKeyPair
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2GenKeyPair
  (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif