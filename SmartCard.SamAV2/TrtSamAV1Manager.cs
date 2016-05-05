using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
//using System.Collections.Generic;
//
using Common.Logging;
//
using SmartCard.Pcsc;
using SmartCard.Player;
//
using Kms2.Crypto.Common;

namespace SmartCard.SamAV2
{
    public class TrtSamAV1Manager : ISamManager
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TrtSamAV1Manager));
        //
        public APDUPlayer ApduPlayer { get; set; }
        public IHexConverter HexConverter { get; set; }
        public IByteWorker ByteWorker { get; set; }
        public IKeyDeriver KeyDeriver { get; set; }
        public IRandWorker RandWorker { get; set; }
        public ISymCryptor AesCryptor { get; set; }
        public ISymCryptor TripleDesCbcCryptor { get; set; }
        public ICMacWorker CMacWorker { get; set; }
        public Iso14443ACrcWorker NxpCrc16Worker { get; set; }
        public Crc32Worker NxpCrc32Worker { get; set; }
        public string ApduURL { get; set; }
        private bool chkOK { get; set; }
        public bool Connect( string apduFile )
        {
            if( null != apduFile )
            {
                this.ApduPlayer.LoadCommandFile( apduFile );
            }
            //
            this.chkOK = false;
            string[] readers = this.ApduPlayer.CardNative.ListReaders();
            if( null == readers )
            {
                log.Error("No reader exists!");
                return false;
            }

            // find first SAM AV2 card
            foreach (string reader in readers)
            {
                try
                {
                    log.Debug(m => m("Connect: [{0}]...", reader));
                    this.ApduPlayer.CardNative.Connect(reader, SHARE.Exclusive, PROTOCOL.T0orT1);
                    byte[] atrValue = this.ApduPlayer.CardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    log.Debug(m => m("ATR:[{0}]", this.HexConverter.Bytes2Hex(atrValue)));
                    if
                    (
                        this.HexConverter.Bytes2Hex(atrValue).StartsWith(
                            "3BDF18FF81F1FE43003F03834D494641524520506C75732053414D3B"
                        )
                    )
                    {
                        log.Debug(m => m("Got {0}...", "SAM_AV2"));
                        this.chkOK = true;
                        break;
                    }
                    else
                    {
                        this.ApduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
                        log.Debug(m => m("reader[{0}]: card unknow!", reader));
                    }
                }
                catch (Exception ex)
                {
                    log.Warn(m => m("{0}", ex.Message));
                }
            }
            if (!this.chkOK)
            {
                log.Debug(m => m("No match card exists!"));
                return false;
            }
            return this.chkOK;
        }
        public bool Connect()
        {
            if (null != this.ApduURL)
            {
                try
                {
                    Assembly thisAssembly = Assembly.GetExecutingAssembly();
                    Stream rgbxml = thisAssembly.GetManifestResourceStream(this.ApduURL);
                    this.ApduPlayer.LoadCommandFile(rgbxml);
                    rgbxml.Close();
                }
                catch (Exception ex)
                {
                    log.Error(ex.StackTrace);
                    return false;
                }
            }
            //
            this.chkOK = false;
            string[] readers = this.ApduPlayer.CardNative.ListReaders();
            if (null == readers)
            {
                log.Error("No reader exists!");
                return false;
            }

            // find first SAM AV2 card
            foreach (string reader in readers)
            {
                try
                {
                    log.Debug(m => m("Connect: [{0}]...", reader));
                    this.ApduPlayer.CardNative.Connect(reader, SHARE.Exclusive, PROTOCOL.T0orT1);
                    byte[] atrValue = this.ApduPlayer.CardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    log.Debug(m => m("ATR:[{0}]", this.HexConverter.Bytes2Hex(atrValue)));
                    if
                    (
                        this.HexConverter.Bytes2Hex(atrValue).StartsWith("3BDF18FF81F1FE43003F03834D494641524520506C75732053414D3B")
                    )
                    {
                        log.Debug(m => m("Got {0}...", "SAM_AV2"));
                        this.chkOK = true;
                        break;
                    }
                    else
                    {
                        this.ApduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
                        log.Debug(m => m("reader[{0}]: card unknow!", reader));
                    }
                }
                catch (Exception ex)
                {
                    log.Warn(m => m("{0}", ex.Message));
                }
            }
            if (!this.chkOK)
            {
                log.Debug(m => m("No match card exists!"));
                return false;
            }
            return this.chkOK;
        }
        public bool AuthenticateHostDefault(AuthHostDO authHostDO)
        {
            // TDES 2key/CBC/no padding, iv all zero, key data: all zero, keyNo: 0x00, keyVer: 0x00,
            byte[] keyData = this.ByteWorker.Fill(16, 0x00);
            byte keyNo = 0x00;
            byte keyVer = 0x00;
            byte authMode  = 0x00;
            //
            return this.AuthenticateHost( keyData, keyNo, keyVer, authMode, authHostDO );
        }
        public byte[] GetUid()
        {
            byte[] version = this.GetVersion();
            if( null != version )
            {
                return this.ByteWorker.SubArray( version, 14, 7 );
            }
            else
            {
                return null;
            }
        }
        public bool Unlock(byte[] keyData, byte keyNo, byte keyVer , byte mode )
        {
            throw new NotImplementedException();
        }
        public void DisConnect()
        {
            this.ApduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
        }
        public bool AuthenticateHost( byte[] keyData, byte keyNo, byte keyVer, byte authMode, AuthHostDO authHostDO )
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m( "SAM_AuthenticateHost_1..."));
            sp.Add( "KNR_KVER", string.Format( "{0:X2}{1:X2}", keyNo, keyVer ));
            sp.Add( "AUTH_MODE", string.Format( "{0:X2}", authMode ) );
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_AuthenticateHost_1", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }
            //
            byte[] iv = this.ByteWorker.Fill(8, 0x00); // TDES 2 key, iv all zero
            this.TripleDesCbcCryptor.SetIv(iv);
            this.TripleDesCbcCryptor.SetKey(keyData);
            authHostDO.RndB = this.TripleDesCbcCryptor.Decrypt(response.Data);
            // 8 bytes random
            authHostDO.RndA = this.RandWorker.GetBytes(8);
            log.Debug(m => m("RndA:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndA)));
            log.Debug(m => m("RndB:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndB)));
            //
            byte[] encRndARndBROL1 = this.TripleDesCbcCryptor.Encrypt
            (
                this.ByteWorker.Combine
                (
                    authHostDO.RndA
                  , this.ByteWorker.RotateLeft(authHostDO.RndB, 1)
                )
            );

            log.Debug(m => m("SAM_AuthenticateHost_2..."));
            sp.Clear();
            sp.Add("MSG", this.HexConverter.Bytes2Hex(encRndARndBROL1));
            response = this.ApduPlayer.ProcessSequence("SAM_AuthenticateHost_2", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //            
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            //
            byte[] encRndAROL1 = response.Data;
            log.Debug(m => m("encRndAROL1:[{0}]", this.HexConverter.Bytes2Hex(encRndAROL1)));
            // if keyData 1st half equal to 2nd half, duplicate session key
            if(this.ByteWorker.AreEqual( this.TripleDesCbcCryptor.Decrypt(encRndAROL1), this.ByteWorker.RotateLeft(authHostDO.RndA, 1)))
            {
                if (this.ByteWorker.AreEqual(this.ByteWorker.SubArray(keyData, 0, 8), this.ByteWorker.SubArray(keyData, 8, 8)))
                {
                    authHostDO.Kxe = this.ByteWorker.Combine
                    (
                        this.ByteWorker.SubArray(authHostDO.RndA, 0, 4)
                      , this.ByteWorker.SubArray(authHostDO.RndB, 0, 4)
                      , this.ByteWorker.SubArray(authHostDO.RndA, 0, 4)
                      , this.ByteWorker.SubArray(authHostDO.RndB, 0, 4)
                    );
                }
                else
                {
                    authHostDO.Kxe = this.ByteWorker.Combine
                    (
                        this.ByteWorker.SubArray(authHostDO.RndA, 0, 4)
                      , this.ByteWorker.SubArray(authHostDO.RndB, 0, 4)
                      , this.ByteWorker.SubArray(authHostDO.RndA, 4, 4)
                      , this.ByteWorker.SubArray(authHostDO.RndB, 4, 4)
                    );
                }
                return true;
            }
            return false;
        }
        public bool AuthenticateHostAES( byte[] keyData, byte keyNo, byte keyVer, byte mode, AuthHostDO authHostDO )
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_AuthenticateHost_1..."));
            sp.Add("KNR_KVER", string.Format("{0:X2}{1:X2}", keyNo, keyVer));
            sp.Add("AUTH_MODE", string.Format("{0:X2}", mode));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_AuthenticateHost_1", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }
            // AES128/CBC
            byte[] iv = this.ByteWorker.Fill(16, 0x00); // block size: 16
            this.AesCryptor.SetIv(iv);
            this.AesCryptor.SetKey(keyData);
            authHostDO.RndB = this.AesCryptor.Decrypt(response.Data);
            // 16 bytes random
            authHostDO.RndA = this.RandWorker.GetBytes(16);
            log.Debug(m => m("RndA:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndA)));
            log.Debug(m => m("RndB:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndB)));
            //
            byte[] encRndARndBROL1 = this.AesCryptor.Encrypt
            (
                this.ByteWorker.Combine
                (
                    authHostDO.RndA
                  , this.ByteWorker.RotateLeft(authHostDO.RndB, 1)
                )
            );

            log.Debug(m => m("SAM_AuthenticateHost_2..."));
            sp.Clear();
            sp.Add("MSG", this.HexConverter.Bytes2Hex(encRndARndBROL1));
            response = this.ApduPlayer.ProcessSequence("SAM_AuthenticateHost_2", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //            
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            //
            byte[] encRndAROL1 = response.Data;
            log.Debug(m => m("encRndAROL1:[{0}]", this.HexConverter.Bytes2Hex(encRndAROL1)));
            if (this.ByteWorker.AreEqual(this.AesCryptor.Decrypt(encRndAROL1), this.ByteWorker.RotateLeft(authHostDO.RndA, 1)))
            {
                authHostDO.Kxe = this.ByteWorker.Combine
                (
                    this.ByteWorker.SubArray(authHostDO.RndA, 0, 4)
                  , this.ByteWorker.SubArray(authHostDO.RndB, 0, 4)
                  , this.ByteWorker.SubArray(authHostDO.RndA, 12, 4)
                  , this.ByteWorker.SubArray(authHostDO.RndB, 12, 4)
                );
                return true;
            }
            return false;
        }
        public byte[] GetVersion()
        {
            //SequenceParameter sp = new SequenceParameter();            
            //sp.Add( "CLA", "83" );
            // APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_GetVersion", sp);
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_GetVersion");
            log.Debug(m => m("Response:[{0}]", response));
            //
            if ((0x90 == response.SW1) && (0x00 == response.SW2))
            {
                return response.Data;
            }
            else
            {
                return null;
            }
        }
        public bool ChangeDefaultMaster(KeyEntryDO keyEntryDO, AuthHostDO authHostDO)
        {
            throw new NotImplementedException();
        }
        public bool ChangeKeyEntry(KeyEntryDO keyEntryDO, AuthHostDO authHostDO)
        {
            // combine key entry
            byte[] keyEntry = this.ByteWorker.Combine
            (
                keyEntryDO.KeyA,
                keyEntryDO.KeyB,
                keyEntryDO.KeyC,
                keyEntryDO.DF_AID,
                new byte[] { keyEntryDO.DF_KEY_NO, keyEntryDO.CEK_NO, keyEntryDO.CEK_VER, keyEntryDO.KUC },
                keyEntryDO.SET,
                new byte[] { keyEntryDO.VerA, keyEntryDO.VerB, keyEntryDO.VerC }
            );
            //
            byte[] crc16 = this.NxpCrc16Worker.ComputeChecksumBytes(keyEntry);
            byte[] decryped = this.ByteWorker.Combine
            (
                keyEntry, crc16, new byte[] { 0x00, 0x00 }
            );
            this.TripleDesCbcCryptor.SetIv(this.ByteWorker.Fill(8, 0x00));
            this.TripleDesCbcCryptor.SetKey(authHostDO.Kxe);
            byte[] encrypted = this.TripleDesCbcCryptor.Encrypt(decryped);
            //
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_ChangeKeyEntry {0}...", keyEntryDO.KeyNo));
            // KNR="00" PROMAS="00" MSG="000000"
            sp.Add("KNR", string.Format("{0:X2}", keyEntryDO.KeyNo));
            sp.Add("PROMAS", "FF");
            sp.Add("MSG", this.HexConverter.Bytes2Hex(encrypted));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_ChangeKeyEntry", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        public KeyEntryDO GetKeyEntry(byte keyNo)
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_GetKeyEntry: 0x{0:X2}...", keyNo));
            sp.Add("KNR", string.Format("{0:X2}", keyNo));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_GetKeyEntry", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return null;
            }
            return
            (
                new KeyEntryDO
                {
                    KeyNo = keyNo,
                    VerA = response.Data[0],
                    VerB = response.Data[1],
                    VerC = response.Data[2],
                    DF_AID = this.ByteWorker.SubArray(response.Data, 3, 3),
                    DF_KEY_NO = response.Data[6],
                    CEK_NO = response.Data[7],
                    CEK_VER = response.Data[8],
                    KUC = response.Data[9],
                    SET = this.ByteWorker.SubArray(response.Data, 10, 2),
                    ExtSet = ((response.Data.Length > 12) ? response.Data[12] : (byte)0)
                }
            );
        }
        public bool ChangeKeyEntryAES(KeyEntryDO keyEntryDO, AuthHostDO authHostDO)
        {
            // combine key entry
            byte[] keyEntry = this.ByteWorker.Combine
            (
                keyEntryDO.KeyA,
                keyEntryDO.KeyB,
                keyEntryDO.KeyC,
                keyEntryDO.DF_AID,
                new byte[] { keyEntryDO.DF_KEY_NO, keyEntryDO.CEK_NO, keyEntryDO.CEK_VER, keyEntryDO.KUC },
                keyEntryDO.SET,
                new byte[] { keyEntryDO.VerA, keyEntryDO.VerB, keyEntryDO.VerC }
            );
            //
            byte[] crc32 = this.NxpCrc32Worker.ComputeChecksumBytes(keyEntry);
            byte[] decryped = this.ByteWorker.Combine
            (
                keyEntry, 
                crc32
            );
            
            this.AesCryptor.SetIv(this.ByteWorker.Fill(16, 0x00));
            this.AesCryptor.SetKey(authHostDO.Kxe);
            byte[] encrypted = this.AesCryptor.Encrypt(decryped);
            //
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_ChangeKeyEntry {0}...", keyEntryDO.KeyNo));
            sp.Add("KNR", string.Format("{0:X2}", keyEntryDO.KeyNo));
            sp.Add("PROMAS", "FF");
            sp.Add("MSG", this.HexConverter.Bytes2Hex(encrypted));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_ChangeKeyEntry", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        public byte[] AuthenticatePICC_1( AuthPICCDO authPICCDO )
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_AuthenticatePICC_1..."));
            sp.Add("AUTH_MODE", string.Format( "{0:X2}", authPICCDO.AuthMode ) ); // 0x11
            byte[] msg = this.ByteWorker.Combine
            (
                 new byte[] { authPICCDO.KeyNo, authPICCDO.KeyVer },
                 authPICCDO.EncRndB,
                 authPICCDO.DivInput
                 //this.HexConverter.Hex2Bytes("D4D795A6B4B259F2961369F9C608600A"),  // encRndB
                 //this.HexConverter.Hex2Bytes("04322222162980494341534804322222162980494341534804322222162980")
            );
            sp.Add("MSG", this.HexConverter.Bytes2Hex(msg));
            APDUResponse response = this.ApduPlayer.ProcessSequence( "SAM_AuthenticatePICC_1", sp );
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return null;
            }
            return response.Data;
        }
        public bool AuthenticatePICC_2( AuthPICCDO authPICCDO )
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_AuthenticatePICC_2..."));
            sp.Add("MSG", this.HexConverter.Bytes2Hex( authPICCDO.EncRndAROL8));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_AuthenticatePICC_2", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                authPICCDO.Kxe = null;
                return false;
            }
            else
            {
                response = this.ApduPlayer.ProcessSequence("SAM_DumpSessionKey");
                if ((0x90 != response.SW1) || (0x00 != response.SW2))
                {
                    authPICCDO.Kxe = null;
                }
                else
                {
                    authPICCDO.Kxe = response.Data;
                }
                return true;
            }
        }

        public byte[] Encrypt(byte keyNo, byte keyVer, byte authMode, byte[] iv, byte[] decrypted)
        {
            SequenceParameter sp = new SequenceParameter();
            // 0x04
            log.Debug(m => m("SAM_Encipher_Data, crypto with secret key..."));            
            sp.Add("KNR_KVER", string.Format( "{0:X2}{1:X2}", keyNo, keyVer ) );
            sp.Add("AUTH_MODE", string.Format("{0:X2}", authMode));
            sp.Add("IV", this.HexConverter.Bytes2Hex(iv));
            sp.Add("MSG", this.HexConverter.Bytes2Hex(decrypted));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_Encipher_Data", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return null;
            }
            return response.Data;
        }


        public KUCDO GetKUCEntry(byte kUCNo)
        {
            log.Debug(m => m("SAM_GetKUCEntry[{0:X2}]...", kUCNo));
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KUCNR", string.Format("{0:X2}", kUCNo));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_GetKUCEntry", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return null;
            }
            return new KUCDO
            {
                KUCNo = kUCNo,
                Limit = BitConverter.ToUInt32( response.Data, 0 ),
                RefKeyNo = response.Data[4],
                RefKeyVer = response.Data[5],
                CurVal = BitConverter.ToUInt32( response.Data, 6) 
            };
        }


        public bool ApplicationExist(byte[] dfAId)
        {
            log.Debug(m => m("SAM_SelectApplication[{0}]...", this.HexConverter.Bytes2Hex( dfAId ) ) );
            SequenceParameter sp = new SequenceParameter();
            sp.Add("DFAID", this.HexConverter.Bytes2Hex(dfAId));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_SelectApplication", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            return true;
        }

        public void ChangeKUCEntry( KUCDO kUCDO, AuthHostDO authHostDO )
        {
            log.Debug(m => m("SAM_ChangeKUCEntry[{0}]...", kUCDO));
            SequenceParameter sp = new SequenceParameter();
            sp.Add( "KUCNR", string.Format("{0:X2}", kUCDO.KUCNo ) );
            sp.Add( "PROMAS", string.Format("{0:X2}", kUCDO.ProMas ));
            // map with promas
            byte[] msg = new byte[] { };
            // update limit
            if( 0x80 == ( 0x80 & kUCDO.ProMas ) )
            {
                msg = this.ByteWorker.Combine( msg, BitConverter.GetBytes( kUCDO.Limit ) );
            }
            // update KeyNoCKUC
            if( 0x40 == ( 0x40 & kUCDO.ProMas ) )
            {
                msg = this.ByteWorker.Combine( msg, new byte[] { kUCDO.RefKeyNo } );
            }
            // update KVerCKUC
            if( 0x20 == ( 0x20 & kUCDO.ProMas ) )
            {
                msg = this.ByteWorker.Combine( msg, new byte[] { kUCDO.RefKeyVer } );
            }
            byte[] crc16 = this.NxpCrc16Worker.ComputeChecksumBytes(msg);
            msg = this.ByteWorker.Combine(msg, crc16);
            log.Debug(m => m("data[{0}]: {1}", msg.Length, this.HexConverter.Bytes2Hex(msg)));
            byte[] decrypted = this.ByteWorker.ZeroPadding( msg, 8, false );
            log.Debug(m => m("{0}", this.HexConverter.Bytes2Hex(decrypted)));
            this.TripleDesCbcCryptor.SetIv(this.ByteWorker.Fill(8, 0x00));
            this.TripleDesCbcCryptor.SetKey( authHostDO.Kxe );
            byte[] encrypted = this.TripleDesCbcCryptor.Encrypt(decrypted);
            sp.Add("MSG", this.HexConverter.Bytes2Hex( encrypted ) );
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_ChangeKUCEntry", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                string errMsg = string.Format( "SAM_ChangeKUCEntry Error: {0:X2}{1:X2}", response.SW1, response.SW2 );
                log.Error(m => m("{0}", errMsg));
                throw new Exception(errMsg);
            }
        }


        public byte[] GetIssuerInfo(byte keyNo, byte keyVer)
        {
            SequenceParameter sp = new SequenceParameter();
            // 0x04
            log.Debug(m => m("SAM_AuthenticateHost_1, crypto with secret key..."));
            sp.Add("KNR_KVER", string.Format("{0:X2}{1:X2}", keyNo, keyVer));
            sp.Add("AUTH_MODE", string.Format("{0:X2}", 0x04));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_AuthenticateHost_1", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return null;
            }
            //log.Debug(m => m("Response:{0}", response.Data));
            //
            response = this.ApduPlayer.ProcessSequence("SAM_DumpSessionKey");
            log.Debug(m => m("RAPDU:[{0}]", response));
            //log.Debug(m => m("Response:{0:X2}{1:X2}", response.SW1, response.SW2));
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return null;
            }
            return response.Data;
        }


        public bool Switch2AV2Mode(byte[] keyData, byte keyVer, AuthHostDO authHostDO)
        {
            throw new NotImplementedException();
        }


        public bool IsAV2Mode()
        {
            byte[] result = this.GetVersion();
            byte lastByte = result[result.Length - 1];
            if (0xA2 == lastByte)
            {
                return true;
            }
            return false;
        }


        public bool KillAuthentication( AuthHostDO authHostDO )
        {
            throw new NotImplementedException();
        }


        public KUCDO GetKUCEntry(byte kUCNo, AuthHostDO authHostDO)
        {
            throw new NotImplementedException();
        }
    }
}
