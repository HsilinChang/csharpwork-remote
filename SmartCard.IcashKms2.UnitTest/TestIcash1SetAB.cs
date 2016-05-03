using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
//
using Spring.Context;
using Spring.Context.Support;
using Common.Logging;
//
using NUnit.Framework;
//
using SmartCard.Pcsc;
using SmartCard.Player;
//using SmartCard.ContactIcash;
using Kms.Crypto;

namespace SmartCard.Player.UnitTest
{
    [TestFixture]
    public class TestIcash1SetAB
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestIcash1SetAB));
        //
        IApplicationContext ctx;
        APDUPlayer apduPlayer = null;
        IHexConverter hexConverter = null;
        IByteWorker byteWorker = null;
        ISymCryptor tripleDesEcbCryptor = null;
        ISymCryptor desEcbCryptor1 = null;
        ISymCryptor desEcbCryptor2 = null;
        ISymCryptor desEcbCryptor3 = null;
        ISymCryptor aes128Cryptor = null;
        IDictionary<string, string> dicKey = new SortedDictionary<string, string>();

        [SetUp]
        public void InitContext()
        {
            bool chkOK = false;            
            //
            this.ctx = ContextRegistry.GetContext();
            this.apduPlayer = ctx["apduPlayer"] as APDUPlayer;
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.tripleDesEcbCryptor = ctx["tripleDesEcbCryptor"] as ISymCryptor;
            this.desEcbCryptor1 = ctx["desEcbCryptor"] as ISymCryptor;
            this.desEcbCryptor2 = ctx["desEcbCryptor"] as ISymCryptor;
            this.desEcbCryptor3 = ctx["desEcbCryptor"] as ISymCryptor;
            this.aes128Cryptor = ctx["symCryptor"] as ISymCryptor;
            //
            this.aes128Cryptor.SetIv(SymCryptor.ConstZero);
            //            
            this.apduPlayer.LoadAPDUFile("CtIcashCmdList.xml");
            this.apduPlayer.LoadSequenceFile("CtIcashCmdList.xml");
            //
            string seedC0Hex =
                "1978042419780424"
              + "1978042419780424"
              + "1978042419780424"
            ;
            // set C0 key
            // IV no need in ECB mode
            this.desEcbCryptor1.SetKey(this.hexConverter.Hex2Bytes(seedC0Hex.Substring(0, 16)));
            this.desEcbCryptor2.SetKey(this.hexConverter.Hex2Bytes(seedC0Hex.Substring(16, 16)));
            this.desEcbCryptor3.SetKey(this.hexConverter.Hex2Bytes(seedC0Hex.Substring(32, 16)));
            //
            string[] readers = this.apduPlayer.CardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            // find first icash card
            foreach (string reader in readers)
            {
                try
                {
                    log.Debug("Connect: [" + reader + "]....");
                    this.apduPlayer.CardNative.Connect(reader, SHARE.Exclusive, PROTOCOL.T0orT1);
                    byte[] atrValue = this.apduPlayer.CardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    log.Debug("ATR:[" + this.hexConverter.Bytes2Hex(atrValue) + "]");
                    if
                    (
                        this.hexConverter.Bytes2Hex(atrValue).StartsWith
                        (
                        //"3BF718000081718042000063950A01900"
                        //"3BF711000081718042000063950A01900"
                        "3BF"
                        )

                    )
                    {
                        log.Debug("Got it...");
                        chkOK = true;
                        break;
                    }
                    else
                    {
                        this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
                    }
                }
                catch (Exception ex)
                {
                    log.Error(ex.Message);
                }
            }
            if (!chkOK)
            {
                log.Debug("No match card exists!");
                return;
            }
        }

        //[Test]
        //public void Test03ReadAllRecords()
        //{
        //    SequenceParameter sp = new SequenceParameter();
        //    sp.Add("DF", "3F00");
        //    APDUResponse response = this.apduPlayer.ProcessSequence("Select_DF", sp);
        //    log.Debug(response);
        //    //
        //    log.Debug("Term Auth C0...");
        //    this.diverseKey();
        //    Assert.IsTrue(this.termAuth(1));
        //    //
        //    log.Debug("Verify Pin C2...");
        //    //Assert.True(this.verifyPin(2, "1234"));
        //    Assert.True(this.verifyPin(2, "bbbbbbbb"));
        //    //
        //    foreach (string keyName in this.dicKey.Keys)
        //    {
        //        log.Debug("Load Key [" + keyName + "]:");
        //        sp.Clear();
        //        sp.Add("EF", dicKey[keyName]);
        //        response = this.apduPlayer.ProcessSequence("ReadKey", sp);
        //        log.Debug(response);
        //        this.parseKey(response.Data);
        //    }

        //}

        [Test]
        public void Test01VerifyPinA()
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", "3F00");
            APDUResponse response = this.apduPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);

            log.Debug("Verify Pin C2...");
            //Assert.True( this.verifyPin( 2, "1234" ) );
            //Assert.True( this.verifyPin( 2, "bbbbbbbb" ) );
            Assert.True(this.verifyPin(2, "aaaaaaaa"));
        }

        [Test]
        public void Test02VerifyPinB()
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", "3F00");
            APDUResponse response = this.apduPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);

            log.Debug("Verify Pin C2...");
            //Assert.True( this.verifyPin( 2, "1234" ) );
            Assert.True( this.verifyPin( 2, "bbbbbbbb" ) );
            //Assert.True(this.verifyPin(2, "aaaaaaaa"));
        }
        private bool verifyPin(uint pq, string pin)
        {
            SequenceParameter sp = new SequenceParameter();
            //
            string pqHex = this.hexConverter.Byte2Hex((byte)(pq << 3));
            byte[] pinBytes = this.byteWorker.Combine
            (
                Encoding.ASCII.GetBytes(pin)
              , this.byteWorker.Fill(8 - pin.Length, 0xFF)
            );
            string pinHex = this.hexConverter.Bytes2Hex(pinBytes);
            //
            sp.Clear();
            sp.Add("PQ", pqHex);
            sp.Add("DATA", pinHex);
            APDUResponse response = this.apduPlayer.ProcessSequence("VerifyPin", sp);
            log.Debug(response);
            return (response.SW1 == 0x90 && response.SW2 == 0x00);
        }

        private void diverseKey()
        {
            // get uid
            byte[] uid = this.getUid("3F00");
            log.Debug("UID:[" + this.hexConverter.Bytes2Hex(uid) + "]");

            // diverse C0 key
            byte[] key1 = this.desEcbCryptor1.Decrypt(uid);
            byte[] key2 = this.desEcbCryptor2.Decrypt(uid);
            byte[] key3 = this.desEcbCryptor3.Decrypt(uid);
            byte[] keyC0 = this.byteWorker.Combine(key1, key2, key3);
            this.tripleDesEcbCryptor.SetKey(keyC0);
            log.Debug("Key C0:[" + this.hexConverter.Bytes2Hex(keyC0) + "]");
        }

        [Test]
        public void Test03TermAuthC0()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            this.diverseKey();
            //
            sp.Add("DF", "3F00");
            response = this.apduPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);
            //
            log.Debug("Term Auth C0...");
            Assert.IsTrue(this.termAuth(1));
        }

        //[Test]
        //public void Test99ListFile()
        //{
        //    SequenceParameter sp = new SequenceParameter();
        //    APDUResponse response = null;
        //    //
        //    sp.Add("DF", "3F00");
        //    response = this.apduPlayer.ProcessSequence("Select_DF", sp);
        //    log.Debug(response);
        //    //
        //    log.Debug("List File....");
        //    sp.Clear();
        //    sp.Add("EF", dicKey[keyName]);
        //    response = this.apduPlayer.ProcessSequence("ReadKey", sp);
        //    log.Debug(response);

        //}
        private bool termAuth(uint kq)
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            // get random
            log.Debug("Gen Random first....");
            response = this.apduPlayer.ProcessSequence("GenRandom");
            log.Debug(response);
            byte[] rndBytes = response.Data;
            byte[] encrypted = this.tripleDesEcbCryptor.Encrypt(rndBytes);
            log.Debug("Encrypted:[" + this.hexConverter.Bytes2Hex(encrypted) + "]");
            //
            log.Debug("Term Auth...");
            sp.Clear();
            string kqHex = this.hexConverter.Byte2Hex((byte)(kq << 3));
            sp.Add("KQ", kqHex);
            sp.Add("DATA", this.hexConverter.Bytes2Hex(encrypted));
            response = this.apduPlayer.ProcessSequence("TermAuth", sp);
            log.Debug(response);
            return (response.SW1 == 0x90 && response.SW2 == 0x00);
        }

        private byte[] getUid(string df)
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", df);
            APDUResponse response = this.apduPlayer.ProcessSequence("ReadBinary", sp);
            log.Debug(response);
            return response.Data;
        }

        //[Test]
        private void parseKey(byte[] rdata)
        {
            int cnt = 0;
            int length = rdata.Length;
            int t = 0;
            int ln = 0;
            byte[] v = null;
            byte[] keyA = null;
            byte[] kaCV = null;
            while (cnt < length)
            {
                t = rdata[cnt++];
                ln = rdata[cnt++];
                v = this.byteWorker.SubArray(rdata, cnt, ln);
                switch ( t )
	            {
                    case 1:
                        keyA = v;
                        log.Debug("RD1 key:[" + this.hexConverter.Bytes2Hex(v) + "]");
                        break;
                    case 2:
                        kaCV = v;
                        log.Debug("RD2 kcv:[" + this.hexConverter.Bytes2Hex(v) + "]");
                        break;
                    case 3:
                        log.Debug("RD3 KCV:[" + this.hexConverter.Bytes2Hex(v) + "]");
                        break;
                    case 4:
                        log.Debug("RD4 KType:[" + this.hexConverter.Bytes2Hex(v) + "]");
                        break;
		            default:
                        break;
	            }                
                cnt += ln;
            }
            //
            this.tripleDesEcbCryptor.SetKey(keyA);
            byte[] encrypted = this.tripleDesEcbCryptor.Encrypt( new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            log.Debug("Encrypted:[" + this.hexConverter.Bytes2Hex(encrypted) + "]");

            Assert.AreEqual(kaCV, this.byteWorker.SubArray(encrypted, 0, 2));
        }

        // 7-11,Card A, DF9501 / EF0021
        // RD1 KEYA:[503AA6C80F44571D503AA6C80F44571D503AA6C80F44571D]
        // RD2 KaCV:[A96A]
        // RD3 KCV:[0AAB]
        // RD4 KType:[03]
        [Test]
        public void Test04ReadKeyEntryA()
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", "3F00");
            APDUResponse response = this.apduPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);
            //
            log.Debug("Term Auth C0...");
            this.diverseKey();
            Assert.IsTrue(this.termAuth(1));
            //
            log.Debug("Verify Pin C2...");
            Assert.True(this.verifyPin(2, "aaaaaaaa"));
            //
            sp.Clear();
            sp.Add("DF", "9501");
            response = this.apduPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);
            //
            log.Debug("Load Key [EF0060]:");
            sp.Clear();
            sp.Add("EF", "0060" );
            response = this.apduPlayer.ProcessSequence("ReadKey", sp);
            log.Debug(response);
            this.parseKey(response.Data);
        }

        // 7-11,Card B, DF9501 / EF0021
        // RD1 KEYB:[EEC1E331193130ECEEC1E331193130ECEEC1E331193130EC]
        // RD2 KbCV:[30C3]
        // RD3 KCV:[0AAB]
        // RD4 KType:[03]
        [Test]
        public void Test05ReadKeyEntryB()
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", "3F00");
            APDUResponse response = this.apduPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);
            //
            log.Debug("Term Auth C0...");
            this.diverseKey();
            Assert.IsTrue(this.termAuth(1));
            //
            log.Debug("Verify Pin C2...");
            Assert.True(this.verifyPin(2, "bbbbbbbb"));
            //
            sp.Clear();
            sp.Add("DF", "9501");
            response = this.apduPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);
            //
            log.Debug("Load Key [EF0060]:");
            sp.Clear();
            sp.Add("EF", "0060");
            response = this.apduPlayer.ProcessSequence("ReadKey", sp);
            log.Debug(response);
            this.parseKey(response.Data);
        }

        [Test]
        public void Test06KCV()
        {
            // 7-11, DF9501 / EF0021
            // RD1 KEYA:[503AA6C80F44571D503AA6C80F44571D503AA6C80F44571D]
            byte[] keyA = this.hexConverter.Hex2Bytes("503AA6C80F44571D503AA6C80F44571D503AA6C80F44571D");
            // RD1 KEYB:[EEC1E331193130ECEEC1E331193130ECEEC1E331193130EC]
            byte[] keyB = this.hexConverter.Hex2Bytes("EEC1E331193130ECEEC1E331193130ECEEC1E331193130EC");
            // RD3 KCV:[0AAB]
            byte[] kcv = this.hexConverter.Hex2Bytes( "0AAB" );
            byte[] key = this.byteWorker.ExclusiveOr(keyA, keyB);
            this.tripleDesEcbCryptor.SetKey(key);
            byte[] result = this.tripleDesEcbCryptor.Encrypt(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            log.Debug( this.hexConverter.Bytes2Hex( result) );
            Assert.AreEqual(kcv, this.byteWorker.SubArray(result, 0, 2));
        }

        [TearDown]
        public void TearDown()
        {
            log.Debug("disconnect...");
            this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
        }
    }
}