using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO.Compression;
using System.IO;
using System.Net;
using SimpleTcp;
namespace SifrelemeOdevi
{
    public class Password
    {
        SimpleTcpServer server;
        public void Server_initiliazer(string ipport)
        {
            server = new SimpleTcpServer(ipport);
            server.Start();
            server.Stop();
        }
        public string sha256Encode(string gelentext)
        {
            SHA256 shasifreleme = new SHA256CryptoServiceProvider();
            byte[] bytedizisi = shasifreleme.ComputeHash(Encoding.UTF8.GetBytes(gelentext));
            StringBuilder builder = new StringBuilder();
            foreach (var item in bytedizisi)
            {
                builder.Append(item.ToString("x2"));    //sha tipinde sifreleme islemi yapıyor.
            }
            return builder.ToString();
        }
        public string SpnEncode(string gelentext ,string key)
        {
            if (gelentext.Length % 2 != 0)
            {
                gelentext += " ";
            }
            string BinaryXor = "", encodingData = "";
            string result="";
            string binaryData = ConvertToBinary(gelentext);
            string dataLength = binaryData;
            string key_bin = ConvertToBinary(key);

            for (int i = 0; i < dataLength.Length; i += 16)   //Girilen değerin uzunluğu kadar döngüye giriyor.
            {
                binaryData = dataLength.Substring(i, 16);     //Girilen değer 2'şer harf olacak şekilde ayrılıyor.

                for (int j = 0; j < 64; j += 16) //Güvenlik Anahtarı 4 kere dönecek şekilde döngüye giriyor.
                {
                    BinaryXor = xorFonksiyonu(binaryData, key_bin.Substring(j, 16));    //Güvenlik anahtarının 2'şer harf olacak şekilde ayrılıyor.

                    if (j < 32)     //1. ve 2. aşamalarda karıştırma işlemi yaptırıyor.
                    {
                        encodingData = SpnMixtoBinary(BinaryXor);
                    }
                    else    // 3. ve 4. aşamalarda (k2,k3) karıştırma işlemi yaptırmıyor.
                    {
                        encodingData = BinaryXor;
                    }

                    binaryData = encodingData;   //Çıkan veriyi binary veri olarak atıyor.

                }
                result += binaryData;    //Sonuca önceki sonuçları ekleyerek işlem yaptırıyor.
            }

            return result;
        }
        public string SpnMixtoBinary(string gelenXOR)
        {
            string geciciDegisken = "";
            geciciDegisken += gelenXOR[2];
            geciciDegisken += gelenXOR[8];
            geciciDegisken += gelenXOR[12];
            geciciDegisken += gelenXOR[5];
            geciciDegisken += gelenXOR[9];
            geciciDegisken += gelenXOR[0];
            geciciDegisken += gelenXOR[14];
            geciciDegisken += gelenXOR[4];
            geciciDegisken += gelenXOR[11]; //Spn algoritmasına göre karıştırma işlemi yapıyor.
            geciciDegisken += gelenXOR[1];
            geciciDegisken += gelenXOR[15];
            geciciDegisken += gelenXOR[6];
            geciciDegisken += gelenXOR[3];
            geciciDegisken += gelenXOR[10];
            geciciDegisken += gelenXOR[7];
            geciciDegisken += gelenXOR[13];

            return geciciDegisken;
        }
        public string xorFonksiyonu(string gelenBinary, string gelenSecurityKey)
        {
            string xorBinary = "";
            for (int i = 0; i < gelenBinary.Length; i++)
            {
                //string ifadenin karakterlerini tek tek alıyor ve xor işlemini yapıyor.
                if (gelenBinary[i] == gelenSecurityKey[i])
                {
                    xorBinary += "0";
                }
                else
                {
                    xorBinary += "1";
                }
            }
            return xorBinary;
        }
        public string ConvertToBinary(string gelendeger)
        {
            string convertValue = "";
            for (int i = 0; i < gelendeger.Length; i++)
            {
                convertValue += Convert.ToString(gelendeger[i], 2).PadLeft(8, '0'); //girilen değeri binary'e çeviriyor.
            }
            return convertValue;
        }
        public string SpnDecode(string val, string key)
        {
            string encoding_result = "";
            string original_result = "";
            string tempValue = "";
            string enterBinary = val;
            string enterBinarySecurityKey;
            string BinaryXor = "", encodingValue = "";

            enterBinarySecurityKey = ConvertToBinary(key);
            for (int i = 0; i < enterBinary.Length; i += 16)      //Girilen değerin uzunluğu kadar döngüye giriyor.
            {
                tempValue = enterBinary.Substring(i, 16);     //Girilen değer 2'şer harf olacak şekilde ayrılıyor.
                for (int j = 48; j >= 0; j -= 16)
                {
                    BinaryXor = xorFonksiyonu(tempValue, enterBinarySecurityKey.Substring(j, 16));
                    //Girilen değerle security key 2'şer harf olacak şekilde ayrılıyor ve xor fonksiyonuna sokuluyor. 
                    if (j == 48 || j == 0)
                    {
                        encodingValue = BinaryXor;    //k3 ve k0 değerleri için karıştırma işlemi yapmıyor.
                    }
                    else
                    {
                        encodingValue = SpnReturnMixtoBinary(BinaryXor);  //k1 ve k2 değerleri için karıştırma işlemi yapıyor.
                    }

                    tempValue = encodingValue;   //Çıkan veriyi binary veri olarak atıyor.

                }

                encoding_result += encodingValue; //Sifrelenmis halini textbox'a yazdırıyor.
            }
            original_result = ConvertToString(encoding_result);
            return original_result;
        }
        public string ConvertToString(string toEncode)
        {
            List<Byte> byteList = new List<Byte>();

            for (int i = 0; i < toEncode.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(toEncode.Substring(i, 8), 2));  //gelen binary'i ascii tablosuna göre karşılığını buluyor.
            }
            return Encoding.ASCII.GetString(byteList.ToArray());
        }
        public string SpnReturnMixtoBinary(string gelenXOR)
        {
            string geciciDegisken = "";
            geciciDegisken += gelenXOR[5];
            geciciDegisken += gelenXOR[9];
            geciciDegisken += gelenXOR[0];
            geciciDegisken += gelenXOR[12];
            geciciDegisken += gelenXOR[7];
            geciciDegisken += gelenXOR[3];
            geciciDegisken += gelenXOR[11];
            geciciDegisken += gelenXOR[14];
            geciciDegisken += gelenXOR[1];  //Spn algoritmasına göre karıştırma işlemini tersine göre yapıyor.
            geciciDegisken += gelenXOR[4];
            geciciDegisken += gelenXOR[13];
            geciciDegisken += gelenXOR[8];
            geciciDegisken += gelenXOR[2];
            geciciDegisken += gelenXOR[15];
            geciciDegisken += gelenXOR[6];
            geciciDegisken += gelenXOR[10];

            return geciciDegisken;
        }
    }
}
