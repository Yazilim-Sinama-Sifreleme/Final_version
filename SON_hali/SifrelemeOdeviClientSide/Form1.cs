using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using SimpleTcp;
namespace SifrelemeOdeviClientSide
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        SimpleTcpClient client;

        #region Binary cevir
        private string BinaryCevir(string toEncode)
        {
            string cevirilenDeger = "";
            for (int i = 0; i < toEncode.Length; i++)
            {
                cevirilenDeger += Convert.ToString(toEncode[i], 2).PadLeft(8, '0'); //girilen değeri binary'e çeviriyor.
            }
            return cevirilenDeger;
        }
        private string StringCevir(string toEncode)
        {
            List<Byte> byteList = new List<Byte>();

            for (int i = 0; i < toEncode.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(toEncode.Substring(i, 8), 2));  //gelen binary'i ascii tablosuna göre karşılığını buluyor.
            }
            return Encoding.ASCII.GetString(byteList.ToArray());
        }
        #endregion

        #region SpnMix
        private string SpnMixtoBinary(string gelenXOR)
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
         #endregion

        #region SpnReturnMixToBinary
            private string SpnReturnMixtoBinary(string gelenXOR)
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
        #endregion

        #region Xor fonksiyonu
        private string xorFonksiyonu(string gelenBinary, string gelenSecurityKey)
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
        #endregion

        #region Sha256 sifreleme
        public string sha256Sifreleme(string gelentext)
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
        #endregion

        #region Spndecode
        private void SpnDecode()
        {
            string geciciDegisken = "";
            string girilenBinary = txtEnterValue.Text;
            string girilenBinarySecurityKey;
            string BinaryXor = "", sifrelenmisVeri = "";


            girilenBinarySecurityKey = BinaryCevir(txtSecurityKey.Text);    //Decode etmek istenilen veriyi binary'e çeviriyor.

            for (int i = 0; i < girilenBinary.Length; i += 16)      //Girilen değerin uzunluğu kadar döngüye giriyor.
            {
                geciciDegisken = girilenBinary.Substring(i, 16);     //Girilen değer 2'şer harf olacak şekilde ayrılıyor.
                for (int j = 48; j >= 0; j -= 16)
                {
                    BinaryXor = xorFonksiyonu(geciciDegisken, girilenBinarySecurityKey.Substring(j, 16));
                    //Girilen değerle security key 2'şer harf olacak şekilde ayrılıyor ve xor fonksiyonuna sokuluyor. 
                    if (j == 48 || j == 0)
                    {
                        sifrelenmisVeri = BinaryXor;    //k3 ve k0 değerleri için karıştırma işlemi yapmıyor.
                    }
                    else
                    {
                        sifrelenmisVeri = SpnReturnMixtoBinary(BinaryXor);  //k1 ve k2 değerleri için karıştırma işlemi yapıyor.
                    }

                    geciciDegisken = sifrelenmisVeri;   //Çıkan veriyi binary veri olarak atıyor.

                }

                txtEncodingResult.Text += sifrelenmisVeri; //Sifrelenmis halini textbox'a yazdırıyor.
            }
            txtOriginalResult.Text = StringCevir(txtEncodingResult.Text);  //Sifrelenmis verinin çözülmüş halini textbox'a yazdırıyor
            txtGetMsg.Text += $"Sunucu :{txtOriginalResult.Text}{Environment.NewLine}"; // server dan gelen şifrelenmiş verinin orjinal halini mesaj görüntüleyici texte atar
            MessageBox.Show("Şifreyi çözme işlemi başarıyla gerçekleşmiştir...", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        #endregion

        #region Spnencode
        public void SpnEncode()
        {
            if (txtEnterValue.Text.Length % 2 != 0)
            {
                txtEnterValue.Text += " ";
            }
            string BinaryXor = "", sifrelenmisVeri = "", sonuc = "";
            string binaryVeri = BinaryCevir(txtEnterValue.Text);
            string veriUzunlugu = binaryVeri;
            string key_bin = BinaryCevir(txtSecurityKey.Text);

            for (int i = 0; i < veriUzunlugu.Length; i += 16)   //Girilen değerin uzunluğu kadar döngüye giriyor.
            {
                binaryVeri = veriUzunlugu.Substring(i, 16);     //Girilen değer 2'şer harf olacak şekilde ayrılıyor.

                for (int j = 0; j < 64; j += 16) //Güvenlik Anahtarı 4 kere dönecek şekilde döngüye giriyor.
                {
                    BinaryXor = xorFonksiyonu(binaryVeri, key_bin.Substring(j, 16));    //Güvenlik anahtarının 2'şer harf olacak şekilde ayrılıyor.

                    if (j < 32)     //1. ve 2. aşamalarda karıştırma işlemi yaptırıyor.
                    {
                        sifrelenmisVeri = SpnMixtoBinary(BinaryXor);
                    }
                    else    // 3. ve 4. aşamalarda (k2,k3) karıştırma işlemi yaptırmıyor.
                    {
                        sifrelenmisVeri = BinaryXor;
                    }

                    binaryVeri = sifrelenmisVeri;   //Çıkan veriyi binary veri olarak atıyor.

                }
                sonuc += binaryVeri;    //Sonuca önceki sonuçları ekleyerek işlem yaptırıyor.
            }

            txtEncodingResult.Text = sonuc; //Sifrelenmis halini textbox'a yazdırıyor.
            MessageBox.Show("Şifreleme işlemi başarıyla gerçekleşmiştir...", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);

        }
        #endregion

        #region Socketprogramming
        private void Form1_Load(object sender, EventArgs e) // form yüklendiğinde soket client nesnesi oluşturulur client connect,disconnect ve veri alıcı event ları eklenir. 
        {
            client = new SimpleTcpClient(txtIpPort.Text);
            client.Events.Connected += Events_Connected; // client connect event 
            client.Events.DataReceived += Events_DataReceived; // client data receiver event
            client.Events.Disconnected += Events_Disconnected; // client disconnect event
            btnDisconnect.Enabled = false;
            btnSend.Enabled = false;
        }

        private void Events_Disconnected(object sender, ClientDisconnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate () // gelen mesaj textine server ile bağlantı kesildi mesajı atanır. bağlantı kesilir
            {
                txtGetMsg.Text += $"Sunucuyla bağlantı kesildi. {Environment.NewLine}";
            });
        }

        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
           
            this.Invoke((MethodInvoker)delegate () // girilen değer textine serverdan gelen şifrelimesaj atanır 
            {
                MessageBox.Show("Sunucudan mesajınız var", "message", MessageBoxButtons.OK, MessageBoxIcon.Information);
                //txtGetMsg.Text += $"Sunucu: {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";
                if (Encoding.UTF8.GetString(e.Data)=="sunucu kapatıldı")
                {
                    txtGetMsg.Text += "sunucu kapatıldı";
                    pcbTick.Visible = false;
                    pcbX.Visible = true;
                    btnSend.Enabled = false;
                    
                }
                else
                {
                    txtEnterValue.Text = $"{Encoding.UTF8.GetString(e.Data)}";

                }
            });
        }

        private void Events_Connected(object sender, ClientConnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate () // gelen mesaj textine server bağlantı bilgisi yazılır server connect işlemi yapılır
            {
                txtGetMsg.Text += $"Sunucuya bağlandı. {Environment.NewLine}";
            });
        }

        private void btnConnect_Click_1(object sender, EventArgs e)
        {
            try
            {
                client.Connect(); // client ilgili ip ve port daki servera bağlanır
                btnSend.Enabled = true;
                btnConnect.Enabled = false;
                btnDisconnect.Enabled = true;
                pcbTick.Visible = true;
                pcbX.Visible = false;
            }
            catch (Exception ex) // ilgili ip veya port boşsa hata mesajı verilir
            {
                MessageBox.Show(ex.Message, "message", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (client.IsConnected) // client servera bağlıysa
            {
                if (!string.IsNullOrEmpty(txtEncodingResult.Text)) // şifrelenmiş halinin boş olup olmadığı kontrol edilir
                {
                    client.Send(txtEncodingResult.Text); // soket aracılığı ile veri aktarımı ilgili server portuna yapılır
                    txtGetMsg.Text += $"sen: {txtEnterValue.Text}{Environment.NewLine}";
                    txtEncodingResult.Clear();
                    txtEnterValue.Clear();
                }
            }
        }
        private void btnDisconnect_Click_1(object sender, EventArgs e)
        {
            if (client.IsConnected)
            {
                client.Disconnect(); // client,server arasındaki soketi kapatır
                btnConnect.Enabled = true;
                pcbX.Visible = true;
                pcbTick.Visible = false;
                btnSend.Enabled = false;
            }
            else
            {
                MessageBox.Show("sunucu ile bağlantı zaten yok","message",MessageBoxButtons.OK,MessageBoxIcon.Error);
            }
        }
        #endregion

        #region Buton işlemleri
        private void btnGeriDonustur_Click(object sender, EventArgs e)
        {
            if (rbSha256.Checked == true)
            {
                MessageBox.Show("Sha256 Decode Edilemez", "HATA", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtEnterValue.Text = "";
            }
            else
            {
                SpnDecode();
                txtEnterValue.Clear();
            }
        }

        private void txtGirilenDeger_Enter(object sender, EventArgs e)
        {
            txtOriginalResult.Text = "";
            txtEncodingResult.Text = "";
        }
        private void btnSifrele_Click(object sender, EventArgs e)
        {
            string donenDeger;
            string enterValue = txtEnterValue.Text;
            string enterSecurityKey = txtSecurityKey.Text;
            if (enterValue == "" || enterValue.Contains("ç") == true || enterValue.Contains("ş") == true || enterValue.Contains("ö") == true || enterValue.Contains("ü") == true || enterValue.Contains("ı") == true || enterValue.Contains("ğ") == true)
            {
                MessageBox.Show("Lütfen şifrelemek istediğiniz alanı boş geçmeyiniz veya türkçe karakterler kullanmayınız", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtEnterValue.Text = "";
            }
            else if (enterSecurityKey.Length<8)
            {
                MessageBox.Show("Lütfen Security Key kısmını boş geçmeyiniz veya 8 harften daha kısa bir değer girmeyiniz", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);

            }
            else
            {
                if (rbSha256.Checked == true)
                {
                    txtOriginalResult.Text = txtEnterValue.Text;
                    donenDeger = sha256Sifreleme(txtEnterValue.Text);    //sha tipinde sifreleme işlemi yapıyor.
                    txtEncodingResult.Text = donenDeger;
                    MessageBox.Show("Şifreleme işlemi başarıyla gerçekleşmiştir...", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    txtOriginalResult.Text = txtEnterValue.Text;
                    SpnEncode();
                }
            }
            
        }
        private void btnCleaner_Click_1(object sender, EventArgs e)
        {
            txtEnterValue.Clear();
            txtEncodingResult.Clear();
            txtOriginalResult.Clear();
            txtGetMsg.Clear();
        }


        #endregion


    }
}
