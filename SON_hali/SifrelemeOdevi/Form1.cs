using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using SimpleTcp;


namespace SifrelemeOdevi
{
    public partial class Form1 : Form
    {
        byte[] abc;
        byte[,] table;
        public Form1()
        {
            InitializeComponent();
        }
        Password ps;
        
        SimpleTcpServer Server;
        #region Binary Çevirme
        private string ConvertToBinary(string toEncode)
        {
            string convertValue = "";
            for (int i = 0; i < toEncode.Length; i++)
            {
                convertValue += Convert.ToString(toEncode[i], 2).PadLeft(8, '0'); //girilen değeri binary'e çeviriyor.
            }
            return convertValue;
        }
        private string ConvertToString(string toEncode)
        {
            List<Byte> byteList = new List<Byte>();

            for (int i = 0; i < toEncode.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(toEncode.Substring(i, 8), 2));  //gelen binary'i ascii tablosuna göre karşılığını buluyor.
            }
            return Encoding.ASCII.GetString(byteList.ToArray());
        }
        #endregion

        #region Sha256 Şifreleme
        private string sha256Encode(string gelentext)
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

        #region SpnEncode
        public void SpnEncode()
        {
            if (txtEnterValue.Text.Length % 2 != 0)
            {
                txtEnterValue.Text += " ";
            }
            string BinaryXor = "", encodingData = "", result="" ;
            string binaryData = ConvertToBinary(txtEnterValue.Text);
            string dataLength = binaryData;
            string key_bin = ConvertToBinary(txtSecurityKey.Text);

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

            txtEncodingResult.Text= result; //Sifrelenmis halini textbox'a yazdırıyor.
            MessageBox.Show("Şifreleme işlemi başarıyla gerçekleşmiştir...", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);

        }

        #endregion

        #region spnDecode
        private void SpnDecode()
        {
            string tempValue = "";
            string enterBinary = txtEnterValue.Text;
            string enterBinarySecurityKey;
            string BinaryXor = "", encodingValue = "";


            enterBinarySecurityKey = ConvertToBinary(txtSecurityKey.Text);    //Decode etmek istenilen veriyi binary'e çeviriyor.

            for (int i = 0; i < enterBinary.Length; i += 16)      //Girilen değerin uzunluğu kadar döngüye giriyor.
            {
                tempValue = enterBinary.Substring(i,16);     //Girilen değer 2'şer harf olacak şekilde ayrılıyor.
                for (int j = 48; j >= 0; j -= 16)   
                {
                    BinaryXor = xorFonksiyonu(tempValue, enterBinarySecurityKey.Substring(j, 16));
                    //Girilen değerle security key 2'şer harf olacak şekilde ayrılıyor ve xor fonksiyonuna sokuluyor. 
                    if (j == 48 || j== 0)
                    {
                        encodingValue = BinaryXor;    //k3 ve k0 değerleri için karıştırma işlemi yapmıyor.
                    }
                    else
                    {
                        encodingValue = SpnReturnMixtoBinary(BinaryXor);  //k1 ve k2 değerleri için karıştırma işlemi yapıyor.
                    }

                    tempValue = encodingValue;   //Çıkan veriyi binary veri olarak atıyor.

                }

                txtEncodingResult.Text += encodingValue; //Sifrelenmis halini textbox'a yazdırıyor.
            }
            txtOriginalResult.Text= ConvertToString(txtEncodingResult.Text);  //Sifrelenmis verinin çözülmüş halini textbox'a yazdırıyor
            txtGetMsg.Text += $"Client :{txtOriginalResult.Text}{Environment.NewLine}"; // client dan gelen şifrelenmiş verinin orjinal halini mesaj görüntüleyici texte atar
            MessageBox.Show("Şifreyi çözme işlemi başarıyla gerçekleşmiştir...", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        #endregion

        #region SPN Mix
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

        #region Spn Return Mix
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

        #region Xor Islemi
        private string xorFonksiyonu(string gelenBinary,string gelenSecurityKey)
        {
            string xorBinary="";
            for (int i = 0; i < gelenBinary.Length; i++)
            {
                //string ifadenin karakterlerini tek tek alıyor ve xor işlemini yapıyor.
                if (gelenBinary[i]==gelenSecurityKey[i])
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

        #region Buton Islemleri

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            string returnValue;
            string enterValue = txtEnterValue.Text;
            string enterSecurityKey = txtSecurityKey.Text;

            if (enterValue == "" || enterValue.Contains("ç") == true || enterValue.Contains("ş") == true || enterValue.Contains("ö") == true || enterValue.Contains("ü") == true || enterValue.Contains("ı") == true || enterValue.Contains("ğ") == true)
            {
                MessageBox.Show("Lütfen şifrelemek istediğiniz alanı boş geçmeyiniz veya türkçe karakterler kullanmayınız...", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtEnterValue.Text = "";
            }
            else if (enterSecurityKey.Length < 8 || enterSecurityKey == "")
            {
                MessageBox.Show("Lütfen Security Key kısmını boş geçmeyiniz veya 8 harften daha kısa bir değer girmeyiniz...", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);

            }
            else
            {
                if (rbSha256.Checked == true)
                {
                    txtOriginalResult.Text = txtEnterValue.Text;
                    returnValue = sha256Encode(txtEnterValue.Text);    //sha tipinde sifreleme işlemi yapıyor.
                    txtEncodingResult.Text = returnValue;
                    MessageBox.Show("Şifreleme işlemi başarıyla gerçekleşmiştir...", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    ps = new Password();
                    txtOriginalResult.Text = txtEnterValue.Text;
                    //SpnEncode();
                   txtEncodingResult.Text= ps.SpnEncode(txtEnterValue.Text, txtSecurityKey.Text);
                }
            }
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            if (rbSha256.Checked == true)
            {
                MessageBox.Show("Sha256 Decode Edilemez", "HATA", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtEnterValue.Text = "";
            }
            else
            {
                ps = new Password();
                txtOriginalResult.Text = ps.SpnDecode(txtEnterValue.Text, txtSecurityKey.Text);
                //SpnDecode(); // şifrelenmiş kodu orjinal haline döniştürür
                txtEnterValue.Clear();
            }
        }

        private void txtEnterValue_Enter(object sender, EventArgs e)
        {
            txtOriginalResult.Text = "";
            txtEncodingResult.Text = "";
        }

        #endregion

        #region Socketprogramming
        private void Form1_Load(object sender, EventArgs e) // form yüklendiğinde server nesnesi ve server alıcıları oluşturuluyor.
        {
            ch_sifrele.Checked = true;
            abc = new byte[256];
            for (int i = 0; i < 256; i++)
                abc[i] = Convert.ToByte(i);

            table = new byte[256, 256];
            for (int i = 0; i < 256; i++)
                for (int j = 0; j < 256; j++)
                {
                    table[i, j] = abc[(i + j) % 256];
                }
            btnSend.Enabled = false;
            Server = new SimpleTcpServer(txtIpPort.Text);
            Server.Events.ClientConnected += Events_ClientConnected; // servera client connect yapılır
            Server.Events.ClientDisconnected += Events_ClientDisconnected; // serverdan client disconnect yapılır
            Server.Events.DataReceived += Events_DataReceived; // client dan veri alıcı yapılır
        }

        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate () // girilen değere client dan alınan şifreli mesaj ataması yapılır
            {
                MessageBox.Show("Client dan mesajınız var", "message", MessageBoxButtons.OK, MessageBoxIcon.Information);
                //txtGetMsg.Text += $"{e.IpPort} : {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";
                txtEnterValue.Text = $"{Encoding.UTF8.GetString(e.Data)}";
            });
        }

        private void Events_ClientDisconnected(object sender, ClientDisconnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate () // gelen mesaj textine clientın disconnect yapıldığı bilgisi yazılır
            {
                txtGetMsg.Text += $"{e.IpPort} Bağlantı kesildi.{Environment.NewLine}";
                lstClietns.Items.Remove(e.IpPort);
            });
        }

        private void Events_ClientConnected(object sender, ClientConnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate () // gelen mesaj textine clientın connect yapıldığı bilgisi yazılır
            {
                txtGetMsg.Text += $"{e.IpPort} Bağlandı. {Environment.NewLine}";
                lstClietns.Items.Add(e.IpPort);
            });
        }

        private void btnStart_Click_1(object sender, EventArgs e)
        {
            Server.Start(); // server başlatılır
            txtGetMsg.Text += $"Başlatılıyor...{Environment.NewLine}";
            btnStart.Enabled = false;
            btnSend.Enabled = true;
            pcbTick.Visible = true;
            pcbX.Visible = false;
        }

        private void btnSend_Click_1(object sender, EventArgs e)
        {
            if (Server.IsListening) // server başlatılmışsa
            {
                if (!string.IsNullOrEmpty(txtEncodingResult.Text) && lstClietns.SelectedItem != null) // şifrelenmiş halinin boş olup olmadığı kontrolü yapılır
                {
                    Server.Send(lstClietns.SelectedItem.ToString(), txtEncodingResult.Text); // soket aracılığı ile veri aktarımı ilgili client portuna yapılır
                    txtGetMsg.Text += $"sunucu: {txtEnterValue.Text}{Environment.NewLine}";
                    txtEncodingResult.Clear();
                    txtEnterValue.Clear();
                }
            }
        }

        private void btnCleaner_Click_1(object sender, EventArgs e)
        {
            lstClietns.Items.Clear();
            txtEnterValue.Clear();
            txtEncodingResult.Clear();
            txtOriginalResult.Clear();
            txtGetMsg.Clear();
        }

        private void btnStop_Click_1(object sender, EventArgs e)
        {
            if (Server.IsListening) // server başlatılmışsa
            {
                for (int i = 0; i <lstClietns.Items.Count; i++)
                {
                    Server.Send(lstClietns.Items[i].ToString(),"sunucu kapatıldı");
                }
               // Server.Send(lstClietns.SelectedItem.ToString(), "Sunucu kapatıldı");
                Server.Stop(); // server kapatılır
                txtGetMsg.Text += $"sunucu durduruldu. {Environment.NewLine}";
                
                btnStart.Enabled = true;
                pcbX.Visible = true;
                pcbTick.Visible = false;
            }
            else
            {
                MessageBox.Show("Sunucu kapatılamaz", "message", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }



        #endregion

        #region Dosya işlemleri

        private void ch_sifrele_CheckedChanged_1(object sender, EventArgs e)
        {
            if (ch_sifrele.Checked)
            {
                ch_Dosya_rarla.Checked = false;
            }
        }

        private void txtFilePath_MouseDoubleClick_1(object sender, MouseEventArgs e)
        {
            OpenFileDialog V1 = new OpenFileDialog();
            V1.Filter = "TEXT files (*.txt)|*txt|All files(*.*)|*.*";

            if (V1.ShowDialog() == DialogResult.OK)
            {
                txtFilePath.Text = Path.GetFileName(V1.FileName);
                txtFilePath.Text = V1.FileName;
            }
        }

        private void ch_Dosya_rarla_CheckedChanged_1(object sender, EventArgs e)
        {
            if (ch_Dosya_rarla.Checked)
            {
                ch_sifrele.Checked = false;
            }
            try
            {
                var fileName = Path.GetFileNameWithoutExtension(txtFilePath.Text);
                var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                var path = Path.Combine(desktop, $"{fileName}.zip");
                using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
                {
                    var entry = archive.CreateEntryFromFile(txtFilePath.Text, Path.GetFileName(txtFilePath.Text), CompressionLevel.Fastest);
                }
            }
            catch (IOException ex)
            {
                MessageBox.Show(ex + "");
            }
        }

        private void btnZipAndCrypt_Click_1(object sender, EventArgs e)
        {
            if (!File.Exists(txtFilePath.Text))
            {
                MessageBox.Show("dosya çıkmıyor.");
                return;
            }
            if (string.IsNullOrEmpty(txtFilePassword.Text))
            {
                MessageBox.Show("Şifre boş lütfen şifreyi giriniz.");
                return;
            }
            try
            {
                byte[] fileContent = File.ReadAllBytes(txtFilePath.Text);
                byte[] passwordTmp = Encoding.ASCII.GetBytes(txtFilePassword.Text);
                byte[] keys = new byte[fileContent.Length];
                for (int i = 0; i < fileContent.Length; i++)
                    keys[i] = passwordTmp[i % passwordTmp.Length];

                //şifrelemek
                byte[] result = new byte[fileContent.Length];
                if (ch_sifrele.Checked)
                {

                    for (int i = 0; i < fileContent.Length; i++)
                    {
                        byte value = fileContent[i];
                        byte key = keys[i];
                        int valueIndex = -1, keyIndex = -1;
                        for (int j = 0; j < 256; j++)
                            if (abc[j] == value)
                            {
                                valueIndex = j;
                                break;
                            }
                        for (int j = 0; j < 256; j++)
                            if (abc[j] == key)
                            {
                                keyIndex = j;
                                break;
                            }
                        result[i] = table[keyIndex, valueIndex];
                    }
                }
                //SifreCözme
                else
                {
                    for (int i = 0; i < fileContent.Length; i++)
                    {
                        byte value = fileContent[i];
                        byte key = keys[i];
                        int valueIndex = -1, keyIndex = -1;
                        for (int j = 0; j < 256; j++)
                            if (abc[j] == key)
                            {
                                keyIndex = j;
                                break;
                            }
                        for (int j = 0; j < 256; j++)
                            if (table[keyIndex, j] == value)
                            {
                                valueIndex = j;
                                break;
                            }
                        result[i] = abc[valueIndex];
                    }
                }
                //aynı uzantıyı kaydet
                string fileExt = Path.GetExtension(txtFilePath.Text);
                SaveFileDialog sd = new SaveFileDialog();
                sd.Filter = "Files(*" + fileExt + ")|*" + fileExt;
                if (sd.ShowDialog() == DialogResult.OK)
                {
                    File.WriteAllBytes(sd.FileName, result);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex + "");
                return;
            }
        }
        #endregion
    }
}
