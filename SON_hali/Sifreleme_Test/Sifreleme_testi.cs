using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using SifrelemeOdevi;
namespace Sifreleme_Test
{
    [TestClass]
    public class Sifreleme_testi
    {
        Form1 form1 = new Form1();
        Password px = new Password();
        //SifrelemeOdevi.Password ps = new SifrelemeOdevi.Password();
        [TestMethod]
        public void object_initiliaze()
        {
            Password ps = new Password();
        }
        [TestMethod]
        public void spnEncode()
        {
            string val = px.SpnEncode("merhaba", "security");
            Assert.AreEqual("1010111001101101000011001100001110101110010100111010111101000011", val);
        }
        [TestMethod]
        public void spnDecode()
        {
            string val = px.SpnDecode("1010111001101101000011001100001110101110010100111010111101000011", "security");
            Assert.AreEqual("merhaba ", val);
        }
        [TestMethod]
        public void sha256()
        {
            string val = px.sha256Encode("merhaba");
            Assert.AreEqual("4c6bcdd55f3153e1939669ab1ec039e4059174dc25abdfcb2f58868849b4d61b", val);
        }
        [TestMethod]
        public void Server_transaction()
        {
            px.Server_initiliazer("127.0.0.1:8888");
        }
    }
}
