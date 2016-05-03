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
    public class TestTrtSamAv1
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestTrtSamAv1));
        //
        private IApplicationContext ctx;
        private ISamManager samAV2Manager = null;
        private IHexConverter hexConverter = null;
        private IByteWorker byteWorker = null;
        private IKeyDeriver keyDeriver;
        private byte[] uid = null;
        //
        private IDictionary<string, KeyInfo> dicKeyInfo = null;//new Dictionary<string, KeyInfo>();
        private IDictionary<string, KeyEntryDO> dicKeyEntry = null; //new Dictionary<string, KeyEntry>();
 
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
            this.samAV2Manager = ctx["trtSamAV1Manager"] as ISamManager;
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
                    DF_AID =  new byte[] { 0x16, 0x87, 0x11 },
                    DF_KEY_NO = 0x0A,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = new byte[] { 0x25, 0x00 },
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
                    DF_AID = new byte[] { 0x16, 0x87, 0x11 },
                    DF_KEY_NO = 0x0B,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = new byte[] { 0x25, 0x00 },
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
                    DF_AID = new byte[] { 0x16, 0x87, 0x11 },
                    DF_KEY_NO = 0x0C,
                    CEK_NO = 0x03,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = new byte[] { 0x25, 0x00 },
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
                    KeyA = this.hexConverter.Hex2Bytes( "A672F20A9062B8FD00D0A592846E881C" ),
                    KeyB = this.hexConverter.Hex2Bytes( "AAD18B1CB1F4CA5CACFF5B4D027DD487" ),
                    KeyC = this.hexConverter.Hex2Bytes( "E6179307E1386459EBD1E5789C29C4A1" ),
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
                    KeyName = "usageKey",
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
                //keyInfo = new KeyInfo
                //{
                //    KeyName = "icashWriteKey",
                //    KeyNo = 0x03,
                //    KeyVer = 0x00,
                //    KeyData = this.hexConverter.Hex2Bytes( "00000000000000000000000000000000" )
                //};
                //this.dicKeyInfo.Add(keyInfo.KeyName, keyInfo);
            }
            // set APDU commands 
            this.samAV2Manager.Connect();
            this.uid = this.samAV2Manager.GetUid();
            log.Debug(m => m("uid: {0}", this.hexConverter.Bytes2Hex(this.uid))); 
        }

        [Test]
        public void Test01GetVersion()
        {
            byte[] version = this.samAV2Manager.GetVersion();
            //byte[] uid = this.samAV2Manager.GetUid();
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

        [Test]
        public void Test02GetUid()
        {
            byte[] uid = this.samAV2Manager.GetUid();
            Assert.NotNull( uid );
            log.Debug(m => m("uid: {0}", this.hexConverter.Bytes2Hex(uid)));            
        }

        [Test]
        public void Test03GetKeyEntry()
        {
            KeyEntryDO keyEntryDO = this.samAV2Manager.GetKeyEntry(0x00);
            log.Debug( m => m( "{0}", keyEntryDO ) );
            keyEntryDO = this.samAV2Manager.GetKeyEntry(0x03);
            log.Debug(m => m("{0}", keyEntryDO));
            for( int i = 00; i <= 128; i++ )
            {
                keyEntryDO = this.samAV2Manager.GetKeyEntry((byte)i);
                log.Debug(m => m("{0}", keyEntryDO));
            }
        }

        //[Test]
        public void Test04AuthHostByUsageKey()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKey"];
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True( this.samAV2Manager.AuthenticateHost( keyInfo.KeyData, keyInfo.KeyNo, keyInfo.KeyVer, 0x00, authHostDO ) );
            log.Debug(m => m("{0}", authHostDO));
        }

        [Test]
        public void Test04AuthHostByIcahWriteKeyTemp()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKey"];
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
            KeyInfo keyInfo = this.dicKeyInfo["usageKey"];
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
            // xor form idx 0..14 => 15
            byte end = keyEntry.KeyA[0];
            for( int i = 1; i < 15; i++ )
            {
                end = (byte)(end ^ keyEntry.KeyA[i]);
            }
            keyEntry.KeyA[15] = end;
            log.Debug(m => m("{0}", keyEntry));
            //
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
                KeyA = this.getDivKey("seedMacKey", "A"),
                KeyB = this.getDivKey("seedMacKey", "B"),
                KeyC = this.getDivKey("seedMacKey", "C"),
                VerA = keyEntry.VerA,
                VerB = keyEntry.VerB,
                VerC = keyEntry.VerC,
                SamMode = keyEntry.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", keyEntry));
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
                KeyA = this.getDivKey("seedWriteKey", "A"),
                KeyB = this.getDivKey("seedWriteKey", "B"),
                KeyC = this.getDivKey("seedWriteKey", "C"),
                VerA = keyEntry.VerA,
                VerB = keyEntry.VerB,
                VerC = keyEntry.VerC,
                SamMode = keyEntry.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", keyEntry));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(divWriteKeyEntry, authHostDO));
        }

        [Test]
        public void Test06AuthHostByIcahWriteKey()
        {
            KeyInfo keyInfo = this.dicKeyInfo["usageKey"];
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
                KeyA = this.getDivKey("seedWriteKey", "A"),
                KeyB = this.getDivKey("seedWriteKey", "B"),
                KeyC = this.getDivKey("seedWriteKey", "C"),
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
        public void Test07ResetWriteKey()
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
                KeyA = this.getDivKey("seedWriteKey", "A"),
                KeyB = this.getDivKey("seedWriteKey", "B"),
                KeyC = this.getDivKey("seedWriteKey", "C"),
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

        [Test]
        public void Test07ResetKeyEntry()
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
                KeyA = this.getDivKey("seedWriteKey", "A"),
                KeyB = this.getDivKey("seedWriteKey", "B"),
                KeyC = this.getDivKey("seedWriteKey", "C"),
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

        private byte[] getDivInput( byte[] uid )
        {
            return this.byteWorker.Combine
            (
                new byte[] { 0x01 }
              , new byte[] { 0x86 }, uid
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

        private byte[] getDivKey( string seedKeyId , string keyVer )
        {
            byte[] seedKey = this.getSeedKey( seedKeyId, keyVer );
            //byte[] uid = this.uid;
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInputIcash( this.uid) );
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug( m => m( "DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey) ) );
            return divKey;
        }
    }

    public class KeyInfo : AbstractDO
    {
        public string KeyName { get; set; }
        public byte KeyNo { get; set; }
        public byte KeyVer { get; set; }
        public byte[] KeyData { get; set; }
    }
}
