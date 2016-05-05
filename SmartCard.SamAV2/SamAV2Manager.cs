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
    public class SamAV2Manager : ISamManager
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(SamAV2Manager));
        //        
        public APDUPlayer ApduPlayer { get; set; }
        public IHexConverter HexConverter { get; set;}
        public IByteWorker ByteWorker { get; set; }
        public IKeyDeriver KeyDeriver { get; set; }
        public IRandWorker RandWorker { get; set; }
        public ISymCryptor AesCryptor { get; set; }
        public ISymCryptor TripleDesCbcCryptor { get; set; }
        public Iso14443ACrcWorker NxpCrc16Worker { get; set; }
        public ICrcWorker<uint> NxpCrc32Worker { get; set; }
        public ICMacWorker CMacWorker { get; set; }
        public string ApduURL { get; set; }
        private bool chkOK { get; set; }
        public bool Connect( string filename )
        {
            if (null != filename )
            {
                this.ApduPlayer.LoadCommandFile(filename);
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
            if( null == readers )
            {
                log.Error( "No reader exists!" );
                return false;
            }
                
            // find first SAM AV2 card
            foreach (string reader in readers)
            {
                try
                {
                    log.Debug( m => m("Connect: [{0}]...", reader) );
                    this.ApduPlayer.CardNative.Connect(reader, SHARE.Exclusive, PROTOCOL.T0orT1);
                    byte[] atrValue = this.ApduPlayer.CardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    log.Debug( m => m("ATR:[{0}]", this.HexConverter.Bytes2Hex(atrValue) ) );
                    if
                    (
                        this.HexConverter.Bytes2Hex(atrValue).StartsWith( "3BDF18FF81F1FE43003F03834D494641524520506C75732053414D3B" )
                    )
                    {
                        log.Debug( m => m( "Got {0}...", "SAM_AV2" ) );
                        this.chkOK = true;
                        break;
                    }
                    else
                    {
                        this.ApduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
                        log.Debug( m => m( "reader[{0}]: card unknow!", reader ) );
                    }
                }
                catch (Exception ex)
                {
                    log.Warn( m => m( "{0}", ex.Message ) );
                }
            }
            if (!this.chkOK)
            {
                log.Debug( m => m( "No match card exists!" ) );
                return false;
            }
            return this.chkOK;
        }
        public bool AuthenticateHostDefault( AuthHostDO authHostDO )
        {
            byte[] keyData = this.ByteWorker.Fill(16, 0x00);
            byte keyNo  = 0x00;
            byte keyVer = 0x00;
            //
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_AuthenticateHost_1..."));
            sp.Add( "KNR_KVER", string.Format("{0:X2}{1:X2}", keyNo, keyVer));
            APDUResponse response = this.ApduPlayer.ProcessSequence( "SAM_AuthenticateHost_1", sp );
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }           
            //
            byte[] iv = this.ByteWorker.Fill(8, 0x00);
            this.TripleDesCbcCryptor.SetIv( iv );
            this.TripleDesCbcCryptor.SetKey( keyData );
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
                  , this.ByteWorker.RotateLeft( authHostDO.RndB, 1 )
                )
            );            

            log.Debug(m => m("SAM_AuthenticateHost_2..."));
            sp.Clear();
            sp.Add( "MSG", this.HexConverter.Bytes2Hex( encRndARndBROL1 ) );
            response = this.ApduPlayer.ProcessSequence("SAM_AuthenticateHost_2", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //            
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            //
            byte[] encRndAROL1 = response.Data;
            log.Debug(m => m( "encRndAROL1:[{0}]", this.HexConverter.Bytes2Hex(encRndAROL1)));
            if( this.ByteWorker.AreEqual( this.TripleDesCbcCryptor.Decrypt( encRndAROL1), this.ByteWorker.RotateLeft( authHostDO.RndA, 1 )))
            {
                // if TDEA 2key the sam...
                authHostDO.Kxe = this.ByteWorker.Combine
                (
                    this.ByteWorker.SubArray(authHostDO.RndA, 0, 4)
                  , this.ByteWorker.SubArray(authHostDO.RndB, 0, 4)
                  , this.ByteWorker.SubArray(authHostDO.RndA, 0, 4)
                  , this.ByteWorker.SubArray(authHostDO.RndB, 0, 4)
                );
                return true;
            }
            return false;
        }
        public byte[] GetUid()
        {
            //log.Debug(m => m("Get UID..."));
            //SequenceParameter sp = new SequenceParameter();            
            //sp.Add( "CLA", "83" );
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_GetVersion"); //,sp);
            log.Debug( m => m( "Response:[{0}]", response ) );
            //
            if( ( 0x90 == response.SW1 ) && ( 0x00 == response.SW2) )
            {
                byte[] resBytes = response.Data;
                //string expected = "0401010302280104010103022801042C2E0AAB36809710250000140B0D00A2";
                return this.ByteWorker.SubArray(resBytes, 14, 7);
            }
            else
            {
                return null;
            }
        }
        public bool Unlock( byte[] keyData, byte keyNo, byte keyVer, byte mode )
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug( m => m( "SAM_Unlock_1..." ) );
            sp.Add( "MODE", string.Format( "{0:X2}", mode ) ); // 0x00
            if (0x00 == mode)
            {
                sp.Add("KNR_KVER", string.Format("{0:X2}{1:X2}", keyNo, keyVer));
            }
            else if( 0x03 == mode )
            {
                sp.Add("KNR_KVER", string.Format("{0:X2}{1:X2}000000", keyNo, keyVer));
            }
            else
            {
                sp.Add("KNR_KVER", string.Format("{0:X2}{1:X2}", keyNo, keyVer ));
            }
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_Unlock_1", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if( ( 0x90 != response.SW1) || ( 0xAF != response.SW2 ) )
            {
                return false;
            }
            // 
            byte[] rnd2 = response.Data;
            byte[] rnd1 = this.RandWorker.GetBytes(12);
            //
            log.Debug( m => m( "Rnd1:[{0}]", this.HexConverter.Bytes2Hex(rnd1)));
            log.Debug( m => m( "Rnd2:[{0}]", this.HexConverter.Bytes2Hex(rnd2)));            
            //
            byte[] iv = this.ByteWorker.Fill( 16, 0x00 );
            this.CMacWorker.SetIv(iv);
            this.CMacWorker.SetMacKey( keyData );
            //
            byte[] macData = this.ByteWorker.Combine(
                    rnd2
                  , new byte[] { mode } // P1
                  , new byte[] { 0x00, 0x00, 0x00 }  //
            );
            this.CMacWorker.DataInput(macData);
            byte[] mact = this.CMacWorker.GetOdd();
            byte[] msg = this.ByteWorker.Combine(
                mact, rnd1
            );

            log.Debug( m => m( "SAM_Unlock_2..."));
            sp.Clear();
            sp.Add( "MSG", this.HexConverter.Bytes2Hex( msg ) );
            response = this.ApduPlayer.ProcessSequence( "SAM_Unlock_2", sp );
            log.Debug( m => m( "RAPDU:[{0}]", response) );
            //            
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }
            //
            byte[] macSam1 = this.ByteWorker.SubArray( response.Data, 0, 8 );
            log.Debug( m => m( "MacSam1:[{0}]", this.HexConverter.Bytes2Hex(macSam1) ) );
            byte[] encSam1 = this.ByteWorker.SubArray( response.Data, 8, 16 );
            log.Debug( m => m( "EncSam1:[{0}]", this.HexConverter.Bytes2Hex(encSam1) ) );
            //
            // verify macSam1
            macData = this.ByteWorker.Combine(
                rnd1
              , new byte[] { mode }
              , new byte[] { 0x00, 0x00, 0x00 }
            );
            this.CMacWorker.DataInput(macData);
            mact = this.CMacWorker.GetOdd();
            if( !this.ByteWorker.AreEqual( mact, macSam1 ) )
            {
                log.Error( m => m( "macSam1 compare error..."));
                return false;
            }
            //
            // decrypt encSam1 with kxe -> rndB, D(kxe,encSam1)
            //    get sv1,Rndl[7..11] || Rnd2[7..11] || ( Rndl[0..4] XOR Rnd2[0..4] ) || 0x91
            // get kxe
            byte[] sv1 = this.ByteWorker.Combine
            (
                this.ByteWorker.SubArray(rnd1, 7, 5)
              , this.ByteWorker.SubArray(rnd2, 7, 5)
              , this.ByteWorker.ExclusiveOr
                (
                    this.ByteWorker.SubArray(rnd1, 0, 5)
                  , this.ByteWorker.SubArray(rnd2, 0, 5)
                )
              , new byte[] { 0x91 }
             );
            log.Debug( m => m( "SV1:[{0}", this.HexConverter.Bytes2Hex(sv1)));
            this.AesCryptor.SetIv(iv);
            this.AesCryptor.SetKey(keyData);
            byte[] kxe = this.AesCryptor.Encrypt(sv1);
            log.Debug( m => m( "Kxe:[{0}]", this.HexConverter.Bytes2Hex(kxe)));
            // decrypt encSam1 with kxe to get rndB
            this.AesCryptor.SetIv(iv);
            this.AesCryptor.SetKey(kxe);
            byte[] rndB = this.AesCryptor.Decrypt(encSam1);            
            //
            byte[] rndA = this.RandWorker.GetBytes(16);
            log.Debug( m => m( "RndA:[{0}]", this.HexConverter.Bytes2Hex(rndA) ) );
            log.Debug(m => m("RndB:[{0}]", this.HexConverter.Bytes2Hex(rndB)));
            // get encHost E(kxe, rndA||rndBROL2)
            byte[] encHost = this.AesCryptor.Encrypt
            (
                this.ByteWorker.Combine
                (
                    rndA, this.ByteWorker.RotateLeft(rndB, 2)
                )
            );
            log.Debug( m => m("Ek(Kxe,RndA||RndB''):[{0}]", this.HexConverter.Bytes2Hex(encHost)));
            //
            log.Debug( m => m( "SAM_Unlock_3..." ) );
            sp.Clear();
            sp.Add("MSG", this.HexConverter.Bytes2Hex( encHost ) );
            response = this.ApduPlayer.ProcessSequence("SAM_Unlock_3", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            // verify RndA from encSam2
            byte[] encSam2 = response.Data;
            byte[] encRndAROL2 = this.AesCryptor.Encrypt(this.ByteWorker.RotateLeft(rndA, 2));
            log.Debug( m => m("Ek(Kxe,RndA''):[{0}]", this.HexConverter.Bytes2Hex(encRndAROL2)));
            return ( this.ByteWorker.AreEqual( encRndAROL2, encSam2 ) );
        }      

        public void DisConnect()
        {
            this.ApduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
        }
        public bool AuthenticateHost( byte[] key, byte keyNo, byte keyVer, byte mode, AuthHostDO authHostDO)
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_AuthenticateHost_1..."));
            sp.Add( "KNR_KVER", string.Format("{0:X2}{1:X2}{2:X2}", keyNo, keyVer, mode ) );
            APDUResponse response = this.ApduPlayer.ProcessSequence( "SAM_AuthenticateHost_1", sp );
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }
            // 
            authHostDO.Rnd2 = response.Data;
            authHostDO.Rnd1 = this.RandWorker.GetBytes(12);
            //            
            log.Debug(m => m("Rnd1:[{0}]", this.HexConverter.Bytes2Hex( authHostDO.Rnd1 ) ) );
            log.Debug(m => m("Rnd2:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.Rnd2)));
            //
            byte[] iv = this.ByteWorker.Fill(16, 0x00);
            this.CMacWorker.SetIv(iv);
            this.CMacWorker.SetMacKey(key);
            //
            byte[] cmacLoad = this.ByteWorker.Combine(
                    authHostDO.Rnd2
                  , new byte[] { mode } // mode
                  , new byte[] { 0x00, 0x00, 0x00 }  // paddings
            );
            this.CMacWorker.DataInput( cmacLoad );
            byte[] mact = this.CMacWorker.GetOdd();
            byte[] msg = this.ByteWorker.Combine(
                mact, authHostDO.Rnd1
            );

            log.Debug(m => m( "SAM_AuthenticateHost_2..." ) );
            sp.Clear();
            sp.Add("MSG", this.HexConverter.Bytes2Hex(msg));
            response = this.ApduPlayer.ProcessSequence( "SAM_AuthenticateHost_2", sp );
            log.Debug(m => m("RAPDU:[{0}]", response));
            //            
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }
            //
            byte[] macSam1 = this.ByteWorker.SubArray(response.Data, 0, 8);
            log.Debug(m => m("MacSam1:[{0}]", this.HexConverter.Bytes2Hex(macSam1)));
            byte[] encSam1 = this.ByteWorker.SubArray(response.Data, 8, 16);
            log.Debug(m => m("EncSam1:[{0}]", this.HexConverter.Bytes2Hex(encSam1)));
            //
            // verify macSam1
            cmacLoad = this.ByteWorker.Combine(
                authHostDO.Rnd1
              , new byte[] { mode }
              , new byte[] { 0x00, 0x00, 0x00 } //padding
            );
            this.CMacWorker.DataInput( cmacLoad );
            mact = this.CMacWorker.GetOdd();
            if (!this.ByteWorker.AreEqual( mact, macSam1 ) )
            {
                log.Error(m => m("macSam1 compare error..."));
                return false;
            }
            //
            // decrypt encSam1 with kxe -> rndB, D(kxe,encSam1)
            //    get sv1,Rndl[7..11] || Rnd2[7..11] || ( Rndl[0..4] XOR Rnd2[0..4] ) || 0x91
            // get kxe
            byte[] sv1 = this.ByteWorker.Combine
            (
                this.ByteWorker.SubArray( authHostDO.Rnd1, 7, 5 )
              , this.ByteWorker.SubArray( authHostDO.Rnd2, 7, 5 )
              , this.ByteWorker.ExclusiveOr
                (
                    this.ByteWorker.SubArray( authHostDO.Rnd1, 0, 5)
                  , this.ByteWorker.SubArray( authHostDO.Rnd2, 0, 5)
                )
              , new byte[] { 0x91 }
             );
            log.Debug(m => m("SV1:[{0}", this.HexConverter.Bytes2Hex(sv1)));
            this.AesCryptor.SetIv(iv);
            this.AesCryptor.SetKey(key);
            authHostDO.Kxe = this.AesCryptor.Encrypt(sv1);
            log.Debug(m => m("Kxe:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.Kxe)));
            // decrypt encSam1 with kxe to get rndB
            this.AesCryptor.SetIv(iv);
            this.AesCryptor.SetKey( authHostDO.Kxe );
            authHostDO.RndB = this.AesCryptor.Decrypt(encSam1);
            authHostDO.RndA = this.RandWorker.GetBytes(16);
            log.Debug(m => m("RndA:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndA)));
            log.Debug(m => m("RndB:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndB)));
            // get encHost E(kxe, rndA||rndBROL2)
            byte[] encHost = this.AesCryptor.Encrypt
            (
                this.ByteWorker.Combine
                (
                    authHostDO.RndA, this.ByteWorker.RotateLeft(authHostDO.RndB, 2)
                )
            );
            log.Debug(m => m("Ek(Kxe,RndA||RndB''):[{0}]", this.HexConverter.Bytes2Hex(encHost)));
            //
            log.Debug( m => m( "SAM_AuthenticateHost_3..." ) );
            sp.Clear();
            sp.Add( "MSG", this.HexConverter.Bytes2Hex(encHost) );
            response = this.ApduPlayer.ProcessSequence("SAM_AuthenticateHost_3", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            // verify RndA from encSam2
            byte[] encSam2 = response.Data;
            //authHostDO.Iv = encSam2;
            byte[] encRndAROL2 = this.AesCryptor.Encrypt(this.ByteWorker.RotateLeft(authHostDO.RndA, 2));
            log.Debug(m => m("Ek(Kxe,RndA''):[{0}]", this.HexConverter.Bytes2Hex(encRndAROL2)));
            if (this.ByteWorker.AreEqual(encRndAROL2, encSam2))
            {
                if (0x02 == mode) // full protection mode, get ke and km
                {
                    this.AesCryptor.SetIv(iv);
                    this.AesCryptor.SetKey(key);
                    byte[] svKe = //RndA[11..15] || RndB[11..15] || ( RndA[4..8] XOR RndB[4..8] ) || 0x81
                        this.ByteWorker.Combine(
                            this.ByteWorker.SubArray(authHostDO.RndA, 11, 5),
                            this.ByteWorker.SubArray(authHostDO.RndB, 11, 5),
                            this.ByteWorker.ExclusiveOr(this.ByteWorker.SubArray(authHostDO.RndA, 4, 5), this.ByteWorker.SubArray(authHostDO.RndB, 4, 5)),
                            new byte[] { 0x81 }
                        );
                    byte[] svKm = //RndA[7..11] || RndB[7..11] ] || ( RndA[0..4] XOR RndB[0..4] ) || 0x82
                        this.ByteWorker.Combine(
                            this.ByteWorker.SubArray(authHostDO.RndA, 7, 5),
                            this.ByteWorker.SubArray(authHostDO.RndB, 7, 5),
                            this.ByteWorker.ExclusiveOr(this.ByteWorker.SubArray(authHostDO.RndA, 0, 5), this.ByteWorker.SubArray(authHostDO.RndB, 0, 5)),
                            new byte[] { 0x82 }
                        );
                    authHostDO.Ke = this.AesCryptor.Encrypt(svKe);
                    authHostDO.Km = this.AesCryptor.Encrypt(svKm);
                }
                authHostDO.CmdCtr = 0;
                return true;
            }
            return false;
        }
        public byte[] GetVersion()
        {            
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_GetVersion"); //,sp);
            log.Debug(m => m("Response:[{0}]", response));
            //
            if ((0x90 == response.SW1) && (0x00 == response.SW2))
            {
                return response.Data;
                //string expected = "0401010302280104010103022801042C2E0AAB36809710250000140B0D00A2";
                //return this.ByteWorker.SubArray(resBytes, 14, 7);
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
                new byte[] { keyEntryDO.VerA, keyEntryDO.VerB, keyEntryDO.VerC } //, keyEntryDO.ExtSet }
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
                    ExtSet = (( response.Data.Length > 12 ) ? response.Data[12] : (byte)0 )
                }
            );
        }

        public bool AuthenticateHostAES(byte[] keyData, byte keyNo, byte keyVer, byte mode, AuthHostDO authHostDO)
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
                new byte[] { keyEntryDO.VerA, keyEntryDO.VerB, keyEntryDO.VerC, keyEntryDO.ExtSet }
            );
            //
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_ChangeKeyEntry {0}...", keyEntryDO.KeyNo));
            // KNR="00" PROMAS="00" MSG="000000"
            sp.Add("KNR", string.Format("{0:X2}", keyEntryDO.KeyNo));
            sp.Add("PROMAS", "FF");
            sp.Add("MSG", this.HexConverter.Bytes2Hex(keyEntry));
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


        public byte[] AuthenticatePICC_1(AuthPICCDO authPICCDO)
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_AuthenticatePICC_1..."));
            sp.Add("AUTH_MODE", string.Format("{0:X2}", authPICCDO.AuthMode)); // 0x11
            byte[] msg = this.ByteWorker.Combine
            (
                 new byte[] { authPICCDO.KeyNo, authPICCDO.KeyVer },
                 authPICCDO.EncRndB,
                 authPICCDO.DivInput
                //this.HexConverter.Hex2Bytes("D4D795A6B4B259F2961369F9C608600A"),  // encRndB
                //this.HexConverter.Hex2Bytes("04322222162980494341534804322222162980494341534804322222162980")
            );
            sp.Add("MSG", this.HexConverter.Bytes2Hex(msg));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_AuthenticatePICC_1", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return null;
            }
            return response.Data;
        }
        public bool AuthenticatePICC_2(AuthPICCDO authPICCDO)
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_AuthenticatePICC_2..."));
            sp.Add("MSG", this.HexConverter.Bytes2Hex(authPICCDO.EncRndAROL8));
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
        public byte[] Encrypt(byte keyNo, byte keyVer, byte divMode, byte[] iv, byte[] decrypted)
        {
            SequenceParameter sp = new SequenceParameter();
            // 0x04
            log.Debug(m => m("SAM_EncipherOffline_Data..."));
            // SAM_EncipherOffline_Data" CLA="80" DIV_MODE="00" KNR_KVER="3500" IV="0000" MSG="0000"
            sp.Add("KNR_KVER", string.Format("{0:X2}{1:X2}", keyNo, keyVer));
            sp.Add("DIV_MODE", string.Format("{0:X2}", divMode ));
            sp.Add("IV", this.HexConverter.Bytes2Hex(iv));
            sp.Add("MSG", this.HexConverter.Bytes2Hex(decrypted));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_EncipherOffline_Data", sp);
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

        public bool ApplicationExist(byte[] DfAid)
        {
            throw new NotImplementedException();
        }

        public void ChangeKUCEntry(KUCDO kUCDO, AuthHostDO authHostDO )
        {
            log.Debug(m => m("SAM_ChangeKUCEntry[{0}]...", kUCDO));
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KUCNR", string.Format("{0:X2}", kUCDO.KUCNo));
            sp.Add("PROMAS", string.Format("{0:X2}", kUCDO.ProMas));
            // map with promas
            byte[] msg = new byte[] { };
            // update limit
            if (0x80 == (0x80 & kUCDO.ProMas))
            {
                msg = this.ByteWorker.Combine(msg, BitConverter.GetBytes(kUCDO.Limit));
            }
            // update KeyNoCKUC
            if (0x40 == (0x40 & kUCDO.ProMas))
            {
                msg = this.ByteWorker.Combine(msg, new byte[] { kUCDO.RefKeyNo });
            }
            // update KVerCKUC
            if (0x20 == (0x20 & kUCDO.ProMas))
            {
                msg = this.ByteWorker.Combine(msg, new byte[] { kUCDO.RefKeyVer });
            }
            // get raw data
            byte[] decrypted = this.ByteWorker.CMacPadding( msg );
            log.Debug(m => m("data[{0}]: {1}", decrypted.Length, this.HexConverter.Bytes2Hex(decrypted)));
            //
            byte[] cntBytes = authHostDO.CmdCtrBytes; //this.ByteWorker.Reverse(BitConverter.GetBytes( counter++ ));
            authHostDO.CmdCtr += 1;
            byte[] ivLoad = this.ByteWorker.Combine
            (
                new byte[] { 0x01, 0x01, 0x01, 0x01 },
                cntBytes, cntBytes, cntBytes
            );            
            //
            this.AesCryptor.SetIv( SymCryptor.ConstZero );
            this.AesCryptor.SetKey( authHostDO.Ke );
            byte[] iv = this.AesCryptor.Encrypt(ivLoad);
            //
            this.AesCryptor.SetIv(iv);
            byte[] encrypted = this.AesCryptor.Encrypt(decrypted);
            // mac data
            byte[] macData = this.ByteWorker.Combine
            (
                new byte[] { 0x80, 0xCC },
                cntBytes,
                new byte[] { kUCDO.KUCNo, kUCDO.ProMas },
                new byte[] { 0x18 },
                encrypted
            );
            this.CMacWorker.SetIv(SymCryptor.ConstZero);
            this.CMacWorker.SetMacKey(authHostDO.Km);
            this.CMacWorker.DataInput(macData);
            byte[] mac = this.CMacWorker.GetOdd();
            //
            byte[] msgFull = this.ByteWorker.Combine(encrypted, mac);
            sp.Add("MSG", this.HexConverter.Bytes2Hex(msgFull));
            APDUResponse response = this.ApduPlayer.ProcessSequence("SAM_ChangeKUCEntry", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                string errMsg = string.Format("SAM_ChangeKUCEntry Error: {0:X2}{1:X2}", response.SW1, response.SW2);
                log.Error(m => m("{0}", errMsg));
                throw new Exception(errMsg);
            }
            else  // verify mac
            {               
                cntBytes = authHostDO.CmdCtrBytes;
                authHostDO.CmdCtr += 1;
                macData = this.ByteWorker.Combine( new byte[] { response.SW1, response.SW2 }, cntBytes );
                this.CMacWorker.DataInput(macData);
                if( !this.ByteWorker.AreEqual(  response.Data, this.CMacWorker.GetOdd() ))
                {
                    string errMsg = string.Format("SAM_ChangeKUCEntry Mac Error..." );
                    log.Error(m => m("{0}", errMsg));
                    throw new Exception(errMsg);
                }
            }
        }


        public byte[] GetIssuerInfo(byte keyNo, byte keyVer)
        {
            throw new NotImplementedException();
        }


        public bool Switch2AV2Mode( byte[] keyData, byte keyVer, AuthHostDO authHostDO )
        {
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug(m => m("SAM_Unlock_1..."));
            byte mode = 0x03;
            sp.Add( "MODE", string.Format("{0:X2}", mode ));
            sp.Add( "KNR_KVER", string.Format( "{0:X2}{1:X2}000000", 0x00, keyVer ) );
            APDUResponse response = this.ApduPlayer.ProcessSequence( "SAM_Unlock_1", sp );
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }
            // 
            authHostDO.Rnd1 = this.RandWorker.GetBytes(12);
            authHostDO.Rnd2 = response.Data;            
            //
            log.Debug(m => m("Rnd1:[{0}]", this.HexConverter.Bytes2Hex( authHostDO.Rnd1)));
            log.Debug(m => m("Rnd2:[{0}]", this.HexConverter.Bytes2Hex( authHostDO.Rnd2)));            
            //
            byte[] iv = this.ByteWorker.Fill(16, 0x00);
            this.CMacWorker.SetIv(iv);
            this.CMacWorker.SetMacKey(keyData);
            //
            byte[] macData = this.ByteWorker.Combine(
                    authHostDO.Rnd2
                  , new byte[] { mode } // P1
                  , new byte[] { 0x00, 0x00, 0x00 }  // MaxChainBlocks
            );
            this.CMacWorker.DataInput(macData);
            byte[] mact = this.CMacWorker.GetOdd();
            byte[] msg = this.ByteWorker.Combine
            (
                mact, authHostDO.Rnd1
            );

            log.Debug(m => m( "SAM_Unlock_2..." ) );
            sp.Clear();
            sp.Add("MSG", this.HexConverter.Bytes2Hex(msg));
            response = this.ApduPlayer.ProcessSequence("SAM_Unlock_2", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //            
            if ((0x90 != response.SW1) || (0xAF != response.SW2))
            {
                return false;
            }
            //
            byte[] macSam1 = this.ByteWorker.SubArray(response.Data, 0, 8);
            log.Debug(m => m("MacSam1:[{0}]", this.HexConverter.Bytes2Hex(macSam1)));
            byte[] encSam1 = this.ByteWorker.SubArray(response.Data, 8, 16);
            log.Debug(m => m("EncSam1:[{0}]", this.HexConverter.Bytes2Hex(encSam1)));
            //
            // verify macSam1
            macData = this.ByteWorker.Combine
            (
                authHostDO.Rnd1
              , new byte[] { mode }
              , new byte[] { 0x00, 0x00, 0x00 }
            );
            this.CMacWorker.DataInput(macData);
            mact = this.CMacWorker.GetOdd();
            if (!this.ByteWorker.AreEqual(mact, macSam1))
            {
                log.Error(m => m("macSam1 compare error..."));
                return false;
            }
            //
            // decrypt encSam1 with kxe -> rndB, D(kxe,encSam1)
            //    get sv1,Rndl[7..11] || Rnd2[7..11] || ( Rndl[0..4] XOR Rnd2[0..4] ) || 0x91
            // get kxe
            byte[] sv1 = this.ByteWorker.Combine
            (
                this.ByteWorker.SubArray( authHostDO.Rnd1, 7, 5)
              , this.ByteWorker.SubArray( authHostDO.Rnd2, 7, 5)
              , this.ByteWorker.ExclusiveOr
                (
                    this.ByteWorker.SubArray( authHostDO.Rnd1, 0, 5)
                  , this.ByteWorker.SubArray( authHostDO.Rnd2, 0, 5)
                )
              , new byte[] { 0x91 }
             );
            log.Debug(m => m("SV1:[{0}", this.HexConverter.Bytes2Hex(sv1)));
            this.AesCryptor.SetIv(iv);
            this.AesCryptor.SetKey( keyData );
            authHostDO.Kxe = this.AesCryptor.Encrypt(sv1);
            log.Debug(m => m("Kxe:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.Kxe)));
            // decrypt encSam1 with kxe to get rndB
            this.AesCryptor.SetIv(iv);
            this.AesCryptor.SetKey(authHostDO.Kxe);
            authHostDO.RndB = this.AesCryptor.Decrypt(encSam1);            
            authHostDO.RndA = this.RandWorker.GetBytes(16);
            log.Debug(m => m("RndA:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndA)));
            log.Debug(m => m("RndB:[{0}]", this.HexConverter.Bytes2Hex(authHostDO.RndB)));
            // get encHost E(kxe, rndA||rndBROL2)
            byte[] encHost = this.AesCryptor.Encrypt
            (
                this.ByteWorker.Combine
                (
                    authHostDO.RndA, this.ByteWorker.RotateLeft(authHostDO.RndB, 2)
                )
            );
            log.Debug(m => m("Ek(Kxe,RndA||RndB''):[{0}]", this.HexConverter.Bytes2Hex(encHost)));
            //
            log.Debug(m => m("SAM_Unlock_3..."));
            sp.Clear();
            sp.Add("MSG", this.HexConverter.Bytes2Hex(encHost));
            response = this.ApduPlayer.ProcessSequence("SAM_Unlock_3", sp);
            log.Debug(m => m("RAPDU:[{0}]", response));
            //
            if ((0x90 != response.SW1) || (0x00 != response.SW2))
            {
                return false;
            }
            // verify RndA from encSam2
            byte[] encSam2 = response.Data;
            byte[] encRndAROL2 = this.AesCryptor.Encrypt(this.ByteWorker.RotateLeft(authHostDO.RndA, 2));
            log.Debug(m => m("Ek(Kxe,RndA''):[{0}]", this.HexConverter.Bytes2Hex(encRndAROL2)));
            return (this.ByteWorker.AreEqual(encRndAROL2, encSam2));
        }


        public bool IsAV2Mode()
        {
            byte[] result = this.GetVersion();
            byte lastByte = result[ result.Length - 1 ];
            if( 0xA2 == lastByte )
            {
                return true;
            }
            return false;
        }


        public bool KillAuthentication( AuthHostDO authHostDO )
        {
            APDUResponse response = null;
            //
            if (null == authHostDO)
            {
                response = this.ApduPlayer.ProcessSequence("SAM_KillAuthentication");
                if ((0x90 != response.SW1) || (0x00 != response.SW2))
                {
                    return false;
                }
                return true;
            }
            else  // full encryption
            {
                byte[] cntBytes = authHostDO.CmdCtrBytes;
                authHostDO.CmdCtr += 1;
                byte[] macData = this.ByteWorker.Combine
                (
                     new byte[] { 0x80, 0xCA }, cntBytes, new byte[] { 0x00, 0x00, 0x08 }
                );
                log.Debug(m => m("{0}", this.HexConverter.Bytes2Hex(macData)));
                this.CMacWorker.SetIv(SymCryptor.ConstZero);
                this.CMacWorker.SetMacKey(authHostDO.Km);
                this.CMacWorker.DataInput(macData);
                byte[] mac = this.CMacWorker.GetOdd();
                //
                SequenceParameter sp = new SequenceParameter();
                sp.Add("MSG", this.HexConverter.Bytes2Hex( mac ));
                response = this.ApduPlayer.ProcessSequence( "SAM_KillAuthentication", sp );
                log.Debug(m => m("RAPDU:[{0}]", response));
                //
                if ((0x90 != response.SW1) || (0x00 != response.SW2))
                {
                    string errMsg = string.Format("SAM_KillAuthentication Error: {0:X2}{1:X2}", response.SW1, response.SW2);
                    log.Error(m => m("{0}", errMsg));
                    throw new Exception(errMsg);
                }
                return true;
            }
        }
    }
}
