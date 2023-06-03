package com.mpei.vkr.magmaencryption.data

import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class MyTrustManager(private val keyStore: KeyStore) : X509TrustManager {

    private val trustManager: X509TrustManager

    init {
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(keyStore)
        trustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        trustManager.checkClientTrusted(chain, authType)
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        try {
            trustManager.checkServerTrusted(chain, authType)
        } catch (e: CertificateException) {
            // If the certificate is not trusted, check if it's in the local KeyStore
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                val cert = keyStore.getCertificate(alias) as X509Certificate
                if (cert.subjectDN == chain?.get(0)?.subjectDN) {
                    return
                }
            }
            throw e
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        return trustManager.acceptedIssuers
    }
}