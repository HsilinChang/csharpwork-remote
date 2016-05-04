using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using System.Security.Cryptography;
//
using Spring.Context;
using Spring.Context.Support;
using Common.Logging;
//
using NUnit.Framework;
//
using SmartCard.Pcsc;
using SmartCard.Player;
using SmartCard.SamAV2;
using Kms2.Crypto.Common;
using Kms2.Crypto.Utility;

namespace SmartCard.SamAV2.UnitTest
{
    [TestFixture]
    public class TestTrtSamAv1Default
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestTrtSamAv1Default));
        //
        private IApplicationContext ctx;
        private TrtSamAV1Manager samAV2Manager = null;
        private IHexConverter hexConverter = null;
        private IByteWorker byteWorker = null;
        private IKeyDeriver keyDeriver;
        private byte[] uid = null;
        private ISymCryptor aesCryptor = null;        
        //
        private IDictionary<string, KeyInfo> dicKeyInfo = null;
        private IDictionary<string, KeyEntryDO> dicKeyEntry = null; 

//        0002	SAM New Card Master Key	
//        01	4631317770440EDA46E875C974ADE505	6370EDC17D695BD4
//        02	75738D8D534FB7EB719DFB749E750428	B6A8B28E76B812EB
//        03	CDD222333ED33527BA289AC6841B210C	43144709EAA85E22
//        0030	Key management(Owner)	
//        01	98AE6B9684B4700E3042AF03E00ADB56	BBD472290AA16F3A
//        02	9C4354F7A862E106F7D483F0731C1A9A	F00E93C01B49D5C8
//        03	CBFA9A3669E3FDAD195D07233928BABA	314EF62B19BA93EE
//        0031	Authenticate with server	
//        01	5C9A1031BE73561663B393DBFEFDEE5A	B69C5E5DE784304B
//        02	6A7C6F50382896440FA76BC1CEF9CFA9	E81949418F90645D
//        03	4AEC089318FDD31D821407158FF13ECB	7EA4439211833F3F
//        0032	Card access-Get Info.(0xA)	
//        01	FDA01F10E42489733FE1EE514AC55E92	90DF1362C2FB2E46
//        02	09DCB16DFBC5D96FCD6BD5E65C337911	E50DE19CBE2FB0E5
//        03	BB24FAB73F9E7BD84951D5754CA36537	CC7F8E7B8EEDECB9
//        0033	Card access-Payment(0xB)	
//        01	EEEA4C617D2880C83BC2358AF645EBDC	FE6D7F606BE91ABE
//        02	9CA1E59063F81D161CAD461F1F437194	59259BDDB23C2643
//        03	7DDE9B3744BD2D5D3B530216FC9014CC	4C6E052BDF464428
//        0034	Card access-Charge(0xC)	
//        01	082CBB7C855C366CCFBF4A07444BA989	17521869272383DF
//        02	55AF06294D9543153B2B5DA825C6AA01	82F0E7FF80F60C9C
//        03	45E1F8444B1344EBAB4273B76780365E	811A683FAB2B62CF
//        0035	TxLog signature TSAM	
//        01	A672F20A9062B8FD00D0A592846E881C	32BCF0C30340F78F
//        02	AAD18B1CB1F4CA5CACFF5B4D027DD487	78FD1CB43CDAE1D8
//        03	E6179307E1386459EBD1E5789C29C4A1	A9D31704246DA508

        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.keyDeriver = ctx["aes128KeyDeriver"] as IKeyDeriver;
            this.samAV2Manager = ctx["trtSamAV1Manager"] as TrtSamAV1Manager;
            this.aesCryptor = ctx["aesCryptor"] as ISymCryptor;
            //
            if (null == this.dicKeyEntry)
            {
                this.dicKeyEntry = new Dictionary<string, KeyEntryDO>();
                // set default keyEntry 
                KeyEntryDO keyEntry = new KeyEntryDO
                {
                    KeyName = "seedWriteKey",
                    KeyNo = 0x03,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0xFF, // 0x01
                    SET = new byte[] { 0x20, 0x04 },
                    KeyA = this.hexConverter.Hex2Bytes( "98AE6B9684B4700E3042AF03E00ADB56" ),
                    KeyB = this.hexConverter.Hex2Bytes( "9C4354F7A862E106F7D483F0731C1A9A" ),
                    KeyC = this.hexConverter.Hex2Bytes( "CBFA9A3669E3FDAD195D07233928BABA" ),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "icashKeyTemp",
                    KeyNo = 0x17,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = new byte[] { 0x00, 0x00 },
                    KeyA = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyB = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyC = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "defaultKey",
                    KeyNo = 0x00,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x00,
                    CEK_VER = 0x00,
                    KUC = 0xFF,
                    SET = new byte[] { 0x00, 0x00 },
                    KeyA = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyB = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyC = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    VerA = 0x00,
                    VerB = 0x00,
                    VerC = 0x00,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "venderKey",
                    KeyNo = 0x17,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0xFF,
                    SET = new byte[] { 0x23, 0x00 },
                    KeyA = this.hexConverter.Hex2Bytes( "010B0300FFFFFFFFFFFFFFFFFFFFFFF6" ),
                    KeyB = this.hexConverter.Hex2Bytes( "00000000000000000000000000000000" ),
                    KeyC = this.hexConverter.Hex2Bytes( "00000000000000000000000000000000" ),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedInfoKey",
                    KeyNo = 0x20,
                    DF_AID =  new byte[] { 0x11, 0x87, 0x16 },
                    DF_KEY_NO = 0x0A,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET =  //new byte[] { 0x25, 0xF8 }, 
                           new byte[] { 0x25, 0x00 },
                    KeyA = this.hexConverter.Hex2Bytes( "FDA01F10E42489733FE1EE514AC55E92" ),
                    KeyB = this.hexConverter.Hex2Bytes( "09DCB16DFBC5D96FCD6BD5E65C337911" ),
                    KeyC = this.hexConverter.Hex2Bytes( "BB24FAB73F9E7BD84951D5754CA36537" ),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedPaymentKey",
                    KeyNo = 0x21,
                    DF_AID = new byte[] { 0x11, 0x87, 0x16 },
                    DF_KEY_NO = 0x0B,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = 
                        //new byte[] { 0x25, 0xF8 }, 
                        new byte[] { 0x25, 0x00 },
                    KeyA = this.hexConverter.Hex2Bytes( "EEEA4C617D2880C83BC2358AF645EBDC" ),
                    KeyB = this.hexConverter.Hex2Bytes( "9CA1E59063F81D161CAD461F1F437194" ),
                    KeyC = this.hexConverter.Hex2Bytes( "7DDE9B3744BD2D5D3B530216FC9014CC" ),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedChargeKey",
                    KeyNo = 0x22,
                    DF_AID = new byte[] { 0x11, 0x87, 0x16 },
                    DF_KEY_NO = 0x0C,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = 
                        //new byte[] { 0x25, 0xF8 }, 
                        new byte[] { 0x25, 0x00 },
                    KeyA = this.hexConverter.Hex2Bytes( "082CBB7C855C366CCFBF4A07444BA989" ),
                    KeyB = this.hexConverter.Hex2Bytes( "55AF06294D9543153B2B5DA825C6AA01" ),
                    KeyC = this.hexConverter.Hex2Bytes( "45E1F8444B1344EBAB4273B76780365E" ),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedMacKey",
                    KeyNo = 0x23,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = new byte[] { 0x22, 0x00 },
                        //new byte[] { 0x20, 0x00 },
                    KeyA = this.hexConverter.Hex2Bytes( "A672F20A9062B8FD00D0A592846E881C" ),
                    KeyB = this.hexConverter.Hex2Bytes( "AAD18B1CB1F4CA5CACFF5B4D027DD487" ),
                    KeyC = this.hexConverter.Hex2Bytes( "E6179307E1386459EBD1E5789C29C4A1" ),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                // add seedMasterKey
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedMasterKey",
                    KeyNo = 0x00,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x00,
                    CEK_VER = 0x00,
                    KUC = 0xFF, 
                    SET = new byte[] { 0x00, 0x04 },
                    KeyA = this.hexConverter.Hex2Bytes("4631317770440EDA46E875C974ADE505"),
                    KeyB = this.hexConverter.Hex2Bytes("75738D8D534FB7EB719DFB749E750428"),
                    KeyC = this.hexConverter.Hex2Bytes("CDD222333ED33527BA289AC6841B210C"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV1"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
            }

            if (null == this.dicKeyInfo)
            {
                this.dicKeyInfo = new Dictionary<string, KeyInfo>();
                // set keyInfo
                KeyInfo keyInfo = new KeyInfo
                {
                    KeyName = "usageKeyDefault",
                    KeyNo = 0x00,
                    KeyVer = 0x00,
                    KeyData = this.hexConverter.Hex2Bytes("00000000000000000000000000000000")
                };
                this.dicKeyInfo.Add(keyInfo.KeyName, keyInfo);
                // 
                keyInfo = new KeyInfo
                {
                    KeyName = "usageKeyTemp",
                    KeyNo = 0x00,
                    KeyVer = 0x01,
                    KeyData = this.hexConverter.Hex2Bytes( "11111111111111111111111111111111" )
                };
                this.dicKeyInfo.Add(keyInfo.KeyName, keyInfo);
                //
                keyInfo = new KeyInfo
                {
                    KeyName = "icashWriteKeyTemp",
                    KeyNo = 0x03,
                    KeyVer = 0x00,
                    KeyData = this.hexConverter.Hex2Bytes( "33333333333333333333333333333333" )
                };
                this.dicKeyInfo.Add(keyInfo.KeyName, keyInfo);
            }
            // set APDU commands 
            this.samAV2Manager.Connect();
            this.uid = this.samAV2Manager.GetUid();
            log.Debug(m => m("uid: {0}", this.hexConverter.Bytes2Hex(this.uid))); 
        }

        //[Test]
        public void Test01GetVersion()
        {
            byte[] version = this.samAV2Manager.GetVersion();
            log.Debug(m => m("version:[{0}]", this.hexConverter.Bytes2Hex(version) ) );
            // 0401010302280104010103022801040C3CE27C20809540580000020B0A00A1
            //       03: TIAD2060
            //         02: TIAD2060
            //           28: 80 KBytes
            // 14..20: uid
            // 30 : A1
            Assert.NotNull(version);
            log.Debug(m => m("uid: {0}", this.hexConverter.Bytes2Hex( this.byteWorker.SubArray(version, 14, 7)) ) );
            if( 0xA1 == version[30] )
            {
                log.Debug(m => m("AV1 mode"));
            }
            else
            {
                log.Debug(m => m("AV2 mode"));
            }
        }

        //[Test]
        public void Test02GetUid()
        {
            byte[] uid = this.samAV2Manager.GetUid();
            Assert.NotNull( uid );
            log.Debug(m => m("uid: {0}", this.hexConverter.Bytes2Hex(uid)));            
        }

        [Test]
        public void Test97SelectApplication()
        {
            // unlock sam
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            //
            bool result = this.samAV2Manager.ApplicationExist(new byte[] { 0x11, 0x87, 0x16 });
            Assert.True(result);
        }

        [Test]
        public void Test96ChangeKUCEntryMax()
        {
            KUCDO kUCDO = new KUCDO
            {
                KUCNo = 0x01,
                ProMas = 0xE0,
                RefKeyNo = 0x00,
                RefKeyVer = 0x00,
                Limit = 0xFFFFFFFF
            };
            // auth default
            //KeyInfo defaultMaster = this.dicKeyInfo["usageKeyTemp"];
            KeyInfo defaultMaster = this.dicKeyInfo["usageKeyDefault"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True( this.samAV2Manager.AuthenticateHost(defaultMaster.KeyData, defaultMaster.KeyNo, defaultMaster.KeyVer, 0x00, authHostDO) );
            this.samAV2Manager.ChangeKUCEntry(kUCDO, authHostDO);
            kUCDO = this.samAV2Manager.GetKUCEntry(0x01);
            log.Debug( m => m( "After Change: {0}", kUCDO ));

        }

        [Test]
        public void Test95ChangeKUCEntryZero()
        {
            KUCDO kUCDO = new KUCDO
            {
                KUCNo = 0x01,
                ProMas = 0xE0,
                RefKeyNo = 0x00,
                RefKeyVer = 0x00, //0x01,
                Limit = 0x00
            };
            // auth default
            KeyInfo defaultMaster = this.dicKeyInfo["usageKeyDefault"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(defaultMaster.KeyData, defaultMaster.KeyNo, defaultMaster.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            this.samAV2Manager.ChangeKUCEntry(kUCDO, authHostDO);
            kUCDO = this.samAV2Manager.GetKUCEntry(0x01);
            log.Debug(m => m("After Change: {0}", kUCDO));

        }

        [Test]
        public void Test98GetKUCEntry()
        {
            KUCDO kUCDO = this.samAV2Manager.GetKUCEntry(0x01);
            log.Debug(m => m("{0}", kUCDO ));
        }

        [Test]
        public void Test99GetKeyEntry()
        {   
            for( int i = 0; i < 128; i++ ) // 0x00 ~ 0xFF
            {
                KeyEntryDO keyEntryDO = this.samAV2Manager.GetKeyEntry((byte)i);
                log.Debug(m => m("{0}", keyEntryDO));
            }
        }

        [Test]
        public void Test01AuthHostByUsageKeyDefault()
        {
            KeyInfo keyInfo = this.dicKeyInfo[ "usageKeyDefault" ];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True( this.samAV2Manager.AuthenticateHost( keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO ) );
            log.Debug(m => m("{0}", authHostDO));
        }

        [Test]
        public void Test02ChangeToTRTCTemp()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyDefault"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));   
            //
            // change vender key entry
            KeyEntryDO keyEntryDO = this.dicKeyEntry["icashKeyTemp"];
            keyEntryDO.KeyNo = 0x17;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntryDO, authHostDO));

            // change info key
            keyEntryDO.KeyNo = 0x20;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntryDO, authHostDO));

            // change payment key
            keyEntryDO.KeyNo = 0x21;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntryDO, authHostDO));

            // change charge key
            keyEntryDO.KeyNo = 0x22;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntryDO, authHostDO));

            // change mac key
            keyEntryDO.KeyNo = 0x23;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntryDO, authHostDO));

            // change write key entry
            keyEntryDO = new KeyEntryDO
            {
                KeyName = "writeKeyTemp",
                KeyNo = 0x03,
                DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                DF_KEY_NO = 0x00,
                CEK_NO = 0x03,
                CEK_VER = 0x00,
                KUC = 0xFF,
                SET = new byte[] { 0x00, 0x04 },
                KeyA = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                KeyB = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                KeyC = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                VerA = 0x00,
                VerB = 0x01,
                VerC = 0x02,
                SamMode = "AV1"
            };
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntryDO, authHostDO));
            // change master key to trtc temp
            keyEntryDO = this.dicKeyEntry["seedMasterKey"];
            KeyEntryDO divMasterKey = new KeyEntryDO
            {
                KeyName = "divMasterKey",
                KeyNo = keyEntryDO.KeyNo,
                DF_AID = keyEntryDO.DF_AID,
                DF_KEY_NO = keyEntryDO.DF_KEY_NO,
                CEK_NO = keyEntryDO.CEK_NO,
                CEK_VER = keyEntryDO.CEK_VER,
                KUC = keyEntryDO.KUC,
                SET = keyEntryDO.SET,
                KeyA = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                KeyB = this.hexConverter.Hex2Bytes("11111111111111111111111111111111"),
                KeyC = this.getDivKeyIcash("seedMasterKey", "C"),
                VerA = keyEntryDO.VerA,
                VerB = keyEntryDO.VerB,
                VerC = keyEntryDO.VerC,
                SamMode = keyEntryDO.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divMasterKey));
            Assert.True(this.samAV2Manager.ChangeKeyEntry( divMasterKey, authHostDO));
        }

        //[Test]
        public void Test04AuthHostByIcahWriteKeyTemp()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            keyInfo = this.dicKeyInfo["icashWriteKeyTemp"];
            authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
        }

        [Test]
        public void Test05ChangeKeyEntry()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            keyInfo = this.dicKeyInfo["icashWriteKeyTemp"];
            authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            
            // change vender key entry
            KeyEntryDO keyEntry = this.dicKeyEntry["venderKey"];           
            keyEntry.KeyA = this.FillIssuerInfo(true);
            log.Debug(m => m("{0}", keyEntry));
            Assert.True( this.samAV2Manager.ChangeKeyEntry(keyEntry, authHostDO) );
            
            // change info key
            keyEntry = this.dicKeyEntry["seedInfoKey"];
            log.Debug(m => m("Change keyentry: {0}", keyEntry));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntry, authHostDO));

            // change payment key
            keyEntry = this.dicKeyEntry["seedPaymentKey"];
            log.Debug(m => m("Change keyentry: {0}", keyEntry));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntry, authHostDO));
            
            // change charge key
            keyEntry = this.dicKeyEntry["seedChargeKey"];
            log.Debug(m => m("Change keyentry: {0}", keyEntry));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntry, authHostDO));
            
            // change mac key
            keyEntry = this.dicKeyEntry["seedMacKey"];
            KeyEntryDO divMacKeyEntry = new KeyEntryDO
            {
                KeyName = "divMacKey",
                KeyNo = keyEntry.KeyNo,
                DF_AID = keyEntry.DF_AID,
                DF_KEY_NO = keyEntry.DF_KEY_NO,
                CEK_NO = keyEntry.CEK_NO,
                CEK_VER = keyEntry.CEK_VER,
                KUC = keyEntry.KUC,
                SET = keyEntry.SET,
                KeyA = this.getDivKey711("seedMacKey", "A"),
                KeyB = this.getDivKey711("seedMacKey", "B"),
                KeyC = this.getDivKey711("seedMacKey", "C"),
                VerA = keyEntry.VerA,
                VerB = keyEntry.VerB,
                VerC = keyEntry.VerC,
                SamMode = keyEntry.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divMacKeyEntry));
            Assert.True(this.samAV2Manager.ChangeKeyEntry( divMacKeyEntry, authHostDO ) );
            
            //change write key, management key
            keyEntry = this.dicKeyEntry["seedWriteKey"];
            KeyEntryDO divWriteKeyEntry = new KeyEntryDO
            {
                KeyName = "divWriteKey",
                KeyNo = keyEntry.KeyNo,
                DF_AID = keyEntry.DF_AID,
                DF_KEY_NO = keyEntry.DF_KEY_NO,
                CEK_NO = keyEntry.CEK_NO,
                CEK_VER = keyEntry.CEK_VER,
                KUC = 0xFF,
                SET = keyEntry.SET,
                KeyA = this.getDivKey711("seedWriteKey", "A"),
                KeyB = this.getDivKey711("seedWriteKey", "B"),
                KeyC = this.getDivKey711("seedWriteKey", "C"),
                VerA = keyEntry.VerA,
                VerB = keyEntry.VerB,
                VerC = keyEntry.VerC,
                SamMode = keyEntry.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divWriteKeyEntry));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(divWriteKeyEntry, authHostDO));
        }

        [Test]
        public void Test06AuthHostByIcahWriteKey()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            //keyInfo = this.dicKeyInfo["icashWriteKey"];
            KeyEntryDO keyEntry = this.dicKeyEntry["seedWriteKey"];
            KeyEntryDO divWriteKeyEntry = new KeyEntryDO
            {
                KeyName = "divWriteKey",
                KeyNo = keyEntry.KeyNo,
                DF_AID = keyEntry.DF_AID,
                DF_KEY_NO = keyEntry.DF_KEY_NO,
                CEK_NO = keyEntry.CEK_NO,
                CEK_VER = keyEntry.CEK_VER,
                KUC = 0xFF,
                SET = keyEntry.SET,
                KeyA = this.getDivKey711("seedWriteKey", "A"),
                KeyB = this.getDivKey711("seedWriteKey", "B"),
                KeyC = this.getDivKey711("seedWriteKey", "C"),
                VerA = keyEntry.VerA,
                VerB = keyEntry.VerB,
                VerC = keyEntry.VerC,
                SamMode = keyEntry.SamMode
            };
            authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHostAES(divWriteKeyEntry.KeyA, 0x03, 0x00, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
        }

        //[Test]
        public void Test00ResetWriteKey()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKey"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            KeyEntryDO keyEntryDO = this.dicKeyEntry["seedWriteKey"];
            KeyEntryDO divWriteKeyEntry = new KeyEntryDO
            {
                KeyName = "divWriteKey",
                KeyNo = keyEntryDO.KeyNo,
                DF_AID = keyEntryDO.DF_AID,
                DF_KEY_NO = keyEntryDO.DF_KEY_NO,
                CEK_NO = keyEntryDO.CEK_NO,
                CEK_VER = keyEntryDO.CEK_VER,
                KUC = 0xFF,
                SET = keyEntryDO.SET,
                KeyA = this.getDivKey711("seedWriteKey", "A"),
                KeyB = this.getDivKey711("seedWriteKey", "B"),
                KeyC = this.getDivKey711("seedWriteKey", "C"),
                VerA = keyEntryDO.VerA,
                VerB = keyEntryDO.VerB,
                VerC = keyEntryDO.VerC,
                SamMode = keyEntryDO.SamMode
            };
            authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHostAES(divWriteKeyEntry.KeyA, 0x03, 0x00, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));

            // change write key entry
            keyEntryDO = new KeyEntryDO
            {
                KeyName = "writeKeyTemp",
                KeyNo = 0x03,
                DF_AID = new byte[] { 0x00, 0x00, 0x00},
                DF_KEY_NO = 0x00,
                CEK_NO = 0x03,
                CEK_VER = 0x00,
                KUC = 0xFF,
                SET = new byte[] { 0x00, 0x04 },
                KeyA = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                KeyB = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                KeyC = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                VerA = 0x00,
                VerB = 0x01,
                VerC = 0x02,
                SamMode = "AV1"
            };            
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES( keyEntryDO, authHostDO));
        }

        //[Test]
        public void Test00ResetKeyEntry()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            KeyEntryDO keyEntryDO = this.dicKeyEntry["seedWriteKey"];
            KeyEntryDO divWriteKeyEntry = new KeyEntryDO
            {
                KeyName = "divWriteKey",
                KeyNo = keyEntryDO.KeyNo,
                DF_AID = keyEntryDO.DF_AID,
                DF_KEY_NO = keyEntryDO.DF_KEY_NO,
                CEK_NO = keyEntryDO.CEK_NO,
                CEK_VER = keyEntryDO.CEK_VER,
                KUC = 0xFF,
                SET = keyEntryDO.SET,
                KeyA = this.getDivKey711("seedWriteKey", "A"),
                KeyB = this.getDivKey711("seedWriteKey", "B"),
                KeyC = this.getDivKey711("seedWriteKey", "C"),
                VerA = keyEntryDO.VerA,
                VerB = keyEntryDO.VerB,
                VerC = keyEntryDO.VerC,
                SamMode = keyEntryDO.SamMode
            };
            authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHostAES(divWriteKeyEntry.KeyA, 0x03, 0x00, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            
            // change vender key entry
            keyEntryDO = this.dicKeyEntry["icashKeyTemp"];
            keyEntryDO.KeyNo = 0x17;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES( keyEntryDO, authHostDO));

            // change info key
            keyEntryDO.KeyNo = 0x20;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change payment key
            keyEntryDO.KeyNo = 0x21;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change charge key
            keyEntryDO.KeyNo = 0x22;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change mac key
            keyEntryDO.KeyNo = 0x23;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change write key entry
            keyEntryDO = new KeyEntryDO
            {
                KeyName = "writeKeyTemp",
                KeyNo = 0x03,
                DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                DF_KEY_NO = 0x00,
                CEK_NO = 0x03,
                CEK_VER = 0x00,
                KUC = 0xFF,
                SET = new byte[] { 0x00, 0x04 },
                KeyA = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                KeyB = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                KeyC = this.hexConverter.Hex2Bytes("33333333333333333333333333333333"),
                VerA = 0x00,
                VerB = 0x01,
                VerC = 0x02,
                SamMode = "AV1"
            };
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));
        }

        [Test]
        public void Test00ResetToDefault()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            KeyEntryDO keyEntryDO = this.dicKeyEntry["seedWriteKey"];
            KeyEntryDO divWriteKeyEntry = new KeyEntryDO
            {
                KeyName = "divWriteKey",
                KeyNo = keyEntryDO.KeyNo,
                DF_AID = keyEntryDO.DF_AID,
                DF_KEY_NO = keyEntryDO.DF_KEY_NO,
                CEK_NO = keyEntryDO.CEK_NO,
                CEK_VER = keyEntryDO.CEK_VER,
                KUC = 0xFF,
                SET = keyEntryDO.SET,
                KeyA = this.getDivKey711("seedWriteKey", "A"),
                KeyB = this.getDivKey711("seedWriteKey", "B"),
                KeyC = this.getDivKey711("seedWriteKey", "C"),
                VerA = keyEntryDO.VerA,
                VerB = keyEntryDO.VerB,
                VerC = keyEntryDO.VerC,
                SamMode = keyEntryDO.SamMode
            };
            authHostDO = new AuthHostDO();
            Assert.True(
                this.samAV2Manager.AuthenticateHostAES
                (
                   divWriteKeyEntry.KeyA,
                   0x03, 0x00, 0x00, authHostDO
                )
            );
            log.Debug(m => m("{0}", authHostDO));

            // change vender key entry
            keyEntryDO = this.dicKeyEntry["defaultKey"];
            keyEntryDO.KeyNo = 0x17;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change info key
            keyEntryDO.KeyNo = 0x20;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change payment key
            keyEntryDO.KeyNo = 0x21;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change charge key
            keyEntryDO.KeyNo = 0x22;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change mac key
            keyEntryDO.KeyNo = 0x23;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));
            // change write key
            keyEntryDO.KeyNo = 0x03;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(keyEntryDO, authHostDO));

            // change master key to default
            keyInfo = this.dicKeyInfo["usageKeyDefault"];
            authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            //KeyEntryDO keyEntryDO = this.dicKeyEntry["defaultKey"];
            keyEntryDO.KeyNo = 0x00;
            log.Debug(m => m("Change keyentry: {0}", keyEntryDO));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(keyEntryDO, authHostDO));
        }

        [Test]
        public void Test08AuthenticatePICC()
        {
            // unlock sam
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            AuthPICCDO authPICCDO = new AuthPICCDO();
            authPICCDO.Uid = "04322222162980";
            byte[] icash2Uid = this.hexConverter.Hex2Bytes(authPICCDO.Uid);
            byte[] divKey = this.getDivKeyIcash( "seedPaymentKey", "A", icash2Uid );
            // 
            authPICCDO.KeyNo = 0x21;
            authPICCDO.KeyVer = 0x00;
            authPICCDO.AuthMode = 0x11;
            authPICCDO.RndB = this.hexConverter.Hex2Bytes( "C6B6CEB30ADCF817775F2BE2D711F3AF" );
            //
            this.aesCryptor.SetIv( SymCryptor.ConstZero );
            this.aesCryptor.SetKey( divKey );
            authPICCDO.EncRndB = this.aesCryptor.Encrypt( authPICCDO.RndB );
            this.aesCryptor.SetIv( authPICCDO.EncRndB ); // keep iv
            // check if encRndB ok!
            Assert.AreEqual( this.hexConverter.Hex2Bytes( "D4D795A6B4B259F2961369F9C608600A" ), authPICCDO.EncRndB );
            //
            authPICCDO.DivInput = this.getDivInputIcash( icash2Uid );
            authPICCDO.EncRndARndBROL8 = this.samAV2Manager.AuthenticatePICC_1( authPICCDO );
            byte[] rndARndBROL8 = this.aesCryptor.Decrypt( authPICCDO.EncRndARndBROL8 );
            this.aesCryptor.SetIv(this.byteWorker.SubArray( authPICCDO.EncRndARndBROL8, 16, 16));
            authPICCDO.RndA = this.byteWorker.SubArray( rndARndBROL8, 0, 16 );
            Assert.AreEqual(this.byteWorker.RotateLeft(authPICCDO.RndB, 1), this.byteWorker.SubArray(rndARndBROL8, 16, 16));
            authPICCDO.EncRndAROL8 = this.aesCryptor.Encrypt( this.byteWorker.RotateLeft( authPICCDO.RndA, 1) );
            bool authOK = this.samAV2Manager.AuthenticatePICC_2( authPICCDO );
            Assert.True(authOK);
            //
            byte[] expected = this.getSessionKey(authPICCDO.RndA, authPICCDO.RndB);
            Assert.AreEqual(expected, authPICCDO.Kxe);
        }


        /// <summary>
        //1. SAM_AuthenticateHost, P1=0x04( AUTH_MODE ) Data= 0x2300 ( KNR_KVER ), 將 0x23 keyA 載入
        //2. SAM_LoadInitVector  Data=0xyyyyMMddHHmmss000000000000000000 (設IV)
        //3. SHA1 txlog data, 取前16 bytes, 份為 Data1, Data2 各 8 bytes
        //4. SAM_Encipher_Data P1=0x00, P2=0x00, Data= Data1 || Data1 || Data2 || Data2, 從結果的 idx 16, 取 4 bytes 做 mac
        /// </summary>
        [Test]
        public void Test09Encrypt()
        {
            // unlock sam
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            //string expected = "CDE4BEAD";
                              //"74335825";
            //string tIdHex = "86041C3E528D3780";

            // transDateTx
            string transDateTxStr = "20150331131600";
            byte[] iv = this.byteWorker.Combine( this.hexConverter.Hex2Bytes(transDateTxStr), this.byteWorker.Fill( 9, 0x00 ) );
            string hashDataStr = "CA199CB285437E416304672EE4D721EFACBD3E4D";
            byte[] hashData = this.hexConverter.Hex2Bytes(hashDataStr);
            byte[] decrypted = this.byteWorker.Combine
            (
                this.byteWorker.SubArray( hashData, 0, 8 ),
                this.byteWorker.SubArray( hashData, 0, 8 ),
                this.byteWorker.SubArray( hashData, 8, 8 ),
                this.byteWorker.SubArray( hashData, 8, 8 )
            );
            byte[] result = this.samAV2Manager.Encrypt(0x23, 0x00, 0x04, iv, decrypted);
            log.Debug(m => m("{0}", this.hexConverter.Bytes2Hex(result)));
            APDULog[] arrayLog = this.samAV2Manager.ApduPlayer.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
            {
                log.Debug( m => m( "{0}", arrayLog[nI] ) );
            }

            this.aesCryptor.SetIv(iv);
            this.aesCryptor.SetKey(this.getDivKey711("seedMacKey", "A"));
            byte[] expected = this.aesCryptor.Encrypt(decrypted);
            Assert.AreEqual( expected, this.byteWorker.SubArray( result, 0, 32 ));
        }

        [Test]
        public void Test10GetIssuerInfo()
        {
            byte[] expected = this.dicKeyEntry["venderKey"].KeyA;
            // unlock sam
            KeyInfo keyInfo = this.dicKeyInfo["usageKeyTemp"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            //
            byte[] result = this.samAV2Manager.GetIssuerInfo(0x17, 0x00);
            Assert.AreEqual(expected, result);
        }


        [TearDown]
        public void TearDown()
        {
            this.samAV2Manager.DisConnect();
        }
        //
        private byte[] getDivInputIcash(byte[] uid)
        {
            return this.byteWorker.Combine
            (
                  uid
                , Encoding.ASCII.GetBytes("ICASH")
                , uid
                , Encoding.ASCII.GetBytes("ICASH")
                , uid
            );
        }

        private byte[] getDivInput711( byte[] uid )
        {
            return this.byteWorker.Combine
            (
                //new byte[] { 0x01 }
                new byte[] { 0x86 }, uid
              , new byte[] { 0x53, 0x45, 0x56, 0x45, 0x4E } // "SEVEN"          
              , new byte[] { 0x86 }, uid
              , new byte[] { 0x31, 0x31 } // "11"
              , new byte[] { 0x86 }, uid
            );
        }
        
        private byte[] getSeedKey( string seedKeyId, string  keyVer )
        {
            byte[] seedKey = null;
            if (this.dicKeyEntry.ContainsKey(seedKeyId))
            {
                if( "A".Equals(keyVer) )
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyA ;
                }
                else if( "B".Equals(keyVer) )
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyB;
                }
                else if ("C".Equals(keyVer))
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyC;
                }
            }
            else
            {
                string errMsg = string.Format( "Seedkey:[{0}], Version:[{1}] not found...", seedKeyId, keyVer );
                throw new Exception( errMsg );
            }
            return seedKey;
        }

        private byte[] getDivKeyIcash( string seedKeyId, string keyVer )
        {
            return this.getDivKeyIcash(seedKeyId, keyVer, null);
        }

        private byte[] getDivKey711(string seedKeyId, string keyVer)
        {
            return this.getDivKey711(seedKeyId, keyVer, null);
        }

        private byte[] getDivKey711(string seedKeyId, string keyVer, byte[] icashUid)
        {
            byte[] seedKey = this.getSeedKey(seedKeyId, keyVer);
            byte[] uid = null;
            if (icashUid == null)
            {
                uid = this.uid;
            }
            else
            {
                uid = icashUid;
            }
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInput711(uid));
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug(m => m("DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey)));
            return divKey;
        }

        private byte[] getDivKeyIcash( string seedKeyId, string keyVer, byte[] icashUid )
        {
            byte[] seedKey = this.getSeedKey( seedKeyId, keyVer );
            byte[] uid = null;
            if (icashUid == null)
            {
                uid = this.uid;
            }
            else
            {
                uid = icashUid;
            }
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInputIcash( uid ) );
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug( m => m( "DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey) ) );
            return divKey;
        }

        private byte[] getSessionKey(byte[] rndA, byte[] rndB)
        {
            return this.byteWorker.Combine
            (
                 this.byteWorker.SubArray(rndA, 0, 4)
                , this.byteWorker.SubArray(rndB, 0, 4)
                , this.byteWorker.SubArray(rndA, 12, 4)
                , this.byteWorker.SubArray(rndB, 12, 4)
            );
        }

        private byte[] FillIssuerInfo( bool isTest )
        {
            byte[] info = this.byteWorker.Fill(16, 0xFF);
            info[0] = 0x01;
            info[1] = 0x0B;
            info[2] = 0x03;
            if( isTest )
            {
                info[3] = 0x00;
            }
            else
            {
                info[3] = 0x42;
            }
            // xor form idx 0..14 => 15
            byte chk = info[0];
            for( int idx = 1; idx < 15; idx++ )
            {
                chk = (byte)(chk ^ info[idx]);
            }
            info[15] = chk;
            return info;
        }
    }
}
