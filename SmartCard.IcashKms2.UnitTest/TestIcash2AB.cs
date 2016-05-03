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
    public class TestIcash2AB
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestIcash2AB));
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
        
            //[ "0036" ] = "0x0,Card Access-AP Master Key";
        
        [SetUp]
        public void InitContext()
        {
            bool chkOK = false;
            dicKey["SAM New Card Master Key"] = "0002";
            dicKey["DESFire New Card Master Key"] = "0004";
            dicKey["0x30,icash2 Key management(Owner)"] = "0030";
            dicKey["0x31,icash2 Authenticate with server"] = "0031";
            dicKey["0x35,icash2 TxLog signature TSAM"] = "0035";
            dicKey["0x00,Card access-AP Master Key"] = "0036";
            dicKey["0x01,Card access-Manufacturer"] = "0037";
            dicKey["0x02,Card access-Format"] = "0038";
            dicKey["0x03,Card access-Private Data"] = "0039";
            dicKey["0x08,Card access-Transport Reading"] = "0010";
            dicKey["0x09,Card access-Transport Writing"] = "0011";
            dicKey["0x0A,Card access-GetInformation"] = "0032";
            dicKey["0x0B,Card access-Payment"] = "0033";
            dicKey["0x0C,Card access-Charge"] = "0034";            
            //
            this.ctx = ContextRegistry.GetContext();
            this.apduPlayer = ctx[ "apduPlayer" ] as APDUPlayer; 
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
                "7ECE2A1CA3C9FE4B"
              + "C90C06BC593C5296"
              + "7CBE5B30D7833BB5"
              //  "1978042419780424"
              //+ "1978042419780424"
              //+ "1978042419780424"
            ;
            // set C0 key
            // IV no need in ECB mode
            this.desEcbCryptor1.SetKey(this.hexConverter.Hex2Bytes(seedC0Hex.Substring(0, 16)));
            this.desEcbCryptor2.SetKey(this.hexConverter.Hex2Bytes(seedC0Hex.Substring(16,16)));
            this.desEcbCryptor3.SetKey(this.hexConverter.Hex2Bytes(seedC0Hex.Substring(32,16))); 
            //
            string[] readers = this.apduPlayer.CardNative.ListReaders();
            if(readers == null)
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
                        //  "3BF71" 
                        "3BFF"
                        //"3BF711000081718042000063950A01900"
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
            if( !chkOK )
            {
                log.Debug("No match card exists!");
                return;
            }
        }

        [Test]
        public void Test03ReadAllRecords()
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
            Assert.True(this.verifyPin(2, "1234"));
            //Assert.True(this.verifyPin(2, "bbbbbbbb"));
            //
            foreach (string keyName in this.dicKey.Keys)
            {
                log.Debug("Load Key [" + keyName + "]:");
                sp.Clear();
                sp.Add("EF", dicKey[keyName]);
                response = this.apduPlayer.ProcessSequence("ReadKey", sp);
                log.Debug(response);
                this.parseKey(response.Data);
            } 

        }

        [Test]
        public void Test01VerifyPin()
        {            
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", "3F00");
            APDUResponse response = this.apduPlayer.ProcessSequence( "Select_DF", sp );
            log.Debug( response );

            log.Debug("Verify Pin C2...");
            Assert.True( this.verifyPin( 2, "1234" ) );
            //Assert.True( this.verifyPin( 2, "bbbbbbbb" ) );
            //Assert.True(this.verifyPin(2, "aaaaaaaa"));
        }

        private bool verifyPin( uint pq, string pin )
        {
            SequenceParameter sp = new SequenceParameter();           
            //
            string pqHex = this.hexConverter.Byte2Hex((byte)(pq << 3));
            byte[] pinBytes = this.byteWorker.Combine
            (
                Encoding.ASCII.GetBytes( pin )
              , this.byteWorker.Fill( 8 - pin.Length, 0xFF )
            );
            string pinHex = this.hexConverter.Bytes2Hex( pinBytes );
            //
            sp.Clear();           
            sp.Add("PQ", pqHex);            
            sp.Add( "DATA", pinHex );
            APDUResponse response = this.apduPlayer.ProcessSequence( "VerifyPin", sp );
            log.Debug(response);   
            return (response.SW1 == 0x90 && response.SW2 == 0x00 );
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
            byte[] keyC0 = this.byteWorker.Combine( key1, key2, key3 );
            this.tripleDesEcbCryptor.SetKey(keyC0);
            log.Debug( "Key C0:[" + this.hexConverter.Bytes2Hex(keyC0)  + "]" );
        }

        [Test]
        public void Test02TermAuthC0()
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
            Assert.IsTrue( this.termAuth(1) );
        }

        private bool termAuth( uint kq )
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
            string kqHex = this.hexConverter.Byte2Hex( (byte)(kq << 3) );
            sp.Add("KQ", kqHex);
            sp.Add("DATA", this.hexConverter.Bytes2Hex(encrypted));
            response = this.apduPlayer.ProcessSequence("TermAuth", sp);
            log.Debug(response);
            return (response.SW1 == 0x90 && response.SW2 == 0x00);
        }

        private byte[] getUid( string df )
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", df);
            APDUResponse response = this.apduPlayer.ProcessSequence("ReadBinary", sp);
            log.Debug(response);            
            return response.Data;
        }

        //[Test]
        private void parseKey( byte[] rdata )
        {
            int cnt = 0;
            int length = rdata.Length;
            int t = 0;
            int ln = 0;
            byte[] v = null;
            while (cnt < length)
            {
                t = rdata[cnt++];
                ln = rdata[cnt++];
                v = this.byteWorker.SubArray(rdata, cnt, ln);
                if (t % 2 == 0)
                {
                    log.Debug("KCV" + t / 2 + ":[" + this.hexConverter.Bytes2Hex(v) + "]");
                }
                else
                {
                    log.Debug("Key" + (t / 2 + 1 ) + ":[" + this.hexConverter.Bytes2Hex(v) + "]");
                }
                cnt += ln;
            }               
        }

        [Test]
        public void Test04VerifyKey()
        {
            string keyAHex1 = "66260D39439907322A0DCF14D1104B20";
               // "AFA90A0058D0FA07B8CAF354BDB8E5C6";
               // "5213D219B252054D1F782F9C3145344F";
            string keyBHex1 = "BA87501603B71B26DA64071B7BB14B0F";
               // "37076196DC648A0988885C575DB23E90";
               // "8CF828FCFB2151BB741E139E5D21BE7F";
            byte[] key1 = this.byteWorker.ExclusiveOr
            (
                this.hexConverter.Hex2Bytes(keyAHex1)
              , this.hexConverter.Hex2Bytes(keyBHex1)
            );
            log.Debug("Key1:[" + this.hexConverter.Bytes2Hex(key1) + "]");
            string expected = "DCA15D2F402E1C14F069C80FAAA1002F";
                //"98AE6B9684B4700E3042AF03E00ADB56";
            Assert.AreEqual(expected, this.hexConverter.Bytes2Hex(key1));
            expected = "9F595CC54945514D";
                //"BBD472290AA16F3A";
            this.aes128Cryptor.SetKey(key1);
            byte[] resultBytes = this.aes128Cryptor.Encrypt(SymCryptor.ConstZero);
            log.Debug("KCV:[" + this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(resultBytes, 0, 8)) + "]");
            Assert.AreEqual(expected, this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(resultBytes, 0, 8)));
            
        }

        //private bool termAuthKey( uint kq )
        //{
        //    SequenceParameter sp = new SequenceParameter();
        //    APDUResponse response = this.apduPlayer.ProcessSequence("ReadBinary");
        //    log.Debug(response);
        //    byte[] uid = response.Data;
        //    log.Debug("UID:[" + this.hexConverter.Bytes2Hex(uid) + "]");

        //    // diverse C0 key
        //    byte[] key1 = this.desEcbCryptor1.Decrypt(uid);
        //    byte[] key2 = this.desEcbCryptor2.Decrypt(uid);
        //    byte[] key3 = this.desEcbCryptor3.Decrypt(uid);
        //    byte[] keyC0 = this.byteWorker.Combine(key1, key2, key3);
        //    this.tripleDesEcbCryptor.SetKey(keyC0);
        //    log.Debug("Key C0:[" + this.hexConverter.Bytes2Hex(keyC0) + "]");

        //    // get random
        //    log.Debug("Gen Random first....");
        //    response = this.apduPlayer.ProcessSequence("GenRandom");
        //    log.Debug(response);
        //    byte[] rndBytes = response.Data;
        //    byte[] encrypted = this.tripleDesEcbCryptor.Encrypt(rndBytes);
        //    log.Debug("Encrypted:[" + this.hexConverter.Bytes2Hex(encrypted) + "]");
        //    //
        //    log.Debug("Term Auth C0...");
        //    sp.Clear();
        //    string kqHex = this.hexConverter.Byte2Hex((byte)(kq << 3));
        //    sp.Add("KQ", kqHex);
        //    sp.Add("DATA", this.hexConverter.Bytes2Hex(encrypted));
        //    response = this.apduPlayer.ProcessSequence("TermAuth", sp);
        //    log.Debug(response);
        //    return (response.SW1 == 0x90 && response.SW2 == 0x00);
        //}

        [Test]
        public void TestListFile()
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DF", "3F00"); //"7110","7011");
            APDUResponse response = this.apduPlayer.ProcessSequence("ListFile", sp);
            log.Debug(response);
        }

        [TearDown]
        public void TearDown()
        {
            log.Debug("disconnect...");
            this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
        }
    }

    class keyPO
    {
        public byte[] Key1 { get; set; }
        public byte[] Kcv1 { get; set; }
        public byte[] Key2 { get; set; }
        public byte[] Kcv2 { get; set; }
        public byte[] Key3 { get; set; }
        public byte[] Kcv3 { get; set; }
    }
}
