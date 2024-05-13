// ライブラリのインポート
import SEAL from 'node-seal'

//非同期関数を定義する
export async function Add() {
    const seal = await SEAL()
    ////////////////////////
    // Encryption Parameters
    ////////////////////////
    
    // 準同型暗号化方式を定義
    const schemeType = seal.SchemeType.bfv    

    // セキュリティレベル(暗号強度)を定義
    const securityLevel = seal.SecurityLevel.tc128


    // 多項式環の次数を定義
    const polyModulusDegree = 4096
    // 多項式環の法を定義
    const bitSizes = [36,36,37]
    // Batching処理に使われる法を定義
    const bitSize = 20
    
    // 値渡し
    const encParms = seal.EncryptionParameters(schemeType)
    encParms.setPolyModulusDegree(polyModulusDegree)
    encParms.setCoeffModulus(
      seal.CoeffModulus.Create(
        polyModulusDegree,
        Int32Array.from(bitSizes)
      )
    )
    encParms.setPlainModulus(
      seal.PlainModulus.Batching(
        polyModulusDegree,
        bitSize
      )
    )

    ////////////////////////
    // Context
    ////////////////////////
    
    // 暗号化パラメータを使用してContextを作成する
    const context = seal.Context(
      encParms,
      true,
      securityLevel
    )

    // Contextが正常に作られたことを確認する
    if (!context.parametersSet()) {
      throw new Error('Could not set the parameters in the given context. Please try different encryption parameters.')
    }

    ////////////////////////
    // Keys
    ////////////////////////
    
    // Contextを元に新しいKeyGeneratorを作成する
    const keyGenerator = seal.KeyGenerator(
      context
    )

    // 秘密鍵を生成
    const Secret_key_Keypair_A_ = keyGenerator.secretKey()

    // 公開鍵を生成
    const Public_key_Keypair_A_ = keyGenerator.createPublicKey()

    //公開鍵の出力
       const publicBase64Key = Public_key_Keypair_A_.save()
       console.log(publicBase64Key)
    

    ////////////////////////
    // Variables
    ////////////////////////

    // 平文を格納する変数
    const PlainText = seal.PlainText();
 
    // 暗号文を格納する変数
    const CipherText = seal.CipherText();

    ////////////////////////
    // Instances
    ////////////////////////

    // 各種演算操作を行う際に利用する
    const evaluator = seal.Evaluator(context)

    // BFV形式で使用される、バッチエンコーダの定義
    const batchEncoder = seal.BatchEncoder(context)

    // 平文を暗号化するために使用される
    const encryptor = seal.Encryptor(
      context,
      Public_key_Keypair_A_
    )

    // 暗号文を復号するために使用される
    const decryptor = seal.Decryptor(
      context,
      Secret_key_Keypair_A_
    )
  
    ////////////////////////
    // Homomorphic Functions
    ////////////////////////
    
    encryptor.encrypt(
      PlainText,
      CipherText
    )
    
    // 平文の定義(多項式である必要があるので、数列を代入する)
    const plainText = batchEncoder.encode(
      Int32Array.from([1, 2, 3 ,4, 5]) // This could also be a Uint32Array
  )

    // 暗号化
    const cipherText = encryptor.encrypt(plainText)
    const cipherTextD = seal.CipherText()

    // 加算
    evaluator.add(cipherText, cipherText, cipherTextD)

    // 復号
    const plainTextD = decryptor.decrypt(cipherTextD)

    // 出力できるようにする
    const decodedA = batchEncoder.decode(plainText)
    const Cipher = cipherText.save()
    const decodedD = batchEncoder.decode(plainTextD)

    console.log('Input:\n',decodedA);
    console.log('Input + Input:\n',decodedD);
    console.log('cipher:\n',Cipher);

    document.getElementById('plaintext').value = decodedA;
    document.getElementById('ciphertext').value = Cipher;
    document.getElementById('results').value = decodedD;

}
