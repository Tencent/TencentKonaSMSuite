package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import javax.crypto.KeyAgreement;

import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for SM2 encryption.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM2KeyAgreementPerfTest {

    private static final String USER_ID = "31323334353637383132333435363738";
    private static final String PRI_KEY
            = "81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029";
    private static final String PUB_KEY
            = "04160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C942324A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F";
    private static final String TMP_PRI_KEY
            = "D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3";
    private static final String TMP_PUB_KEY
            = "0464CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0";

    private static final String PEER_USER_ID = "31323334353637383132333435363738";
    private static final String PEER_PRI_KEY
            = "785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5";
    private static final String PEER_PUB_KEY
            = "046AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFBEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D";
    private static final String PEER_TMPPRIKEY
            = "7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6";
    private static final String PEER_TMP_PUB_KEY
            = "04ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE";

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class KeyAgreementHolder {

        KeyAgreement keyAgreement;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                    toBytes(USER_ID),
                    new SM2PrivateKey(toBytes(PRI_KEY)),
                    new SM2PublicKey(toBytes(PUB_KEY)),
                    toBytes(PEER_USER_ID),
                    new SM2PublicKey(toBytes(PEER_PUB_KEY)),
                    true,
                    32);
            keyAgreement = KeyAgreement.getInstance("SM2");
            keyAgreement.init(
                    new SM2PrivateKey(toBytes(TMP_PRI_KEY)), paramSpec);
            keyAgreement.doPhase(new SM2PublicKey(toBytes(TMP_PUB_KEY)), true);
        }
    }

    @Benchmark
    public byte[] generateSecret(KeyAgreementHolder holder) {
        return holder.keyAgreement.generateSecret();
    }
}
