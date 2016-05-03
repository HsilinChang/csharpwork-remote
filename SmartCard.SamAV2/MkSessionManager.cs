using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
//
using Common.Logging;
using Kms2.Crypto.Common;
using Kms2.Crypto.Utility;
using Newtonsoft.Json;

namespace SmartCard.SamAV2
{
    public class MkSessionManager : IMkSessionManager
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(MkSessionManager));
        public RndMapper RndMapper { get; set; }
        public IByteWorker ByteWorker { get; set; }
        public IHexConverter HexConverter { get; set; }
        public ISymCryptor AesCryptor { get; set; }
        public IHashWorker HashWorker { get; set; }

        private IDictionary<string, byte[]> mkDic = new Dictionary<string, byte[]>();
            
        private KeyCardDO keyCardDO = null;

        public bool SetKeyCard(string keyCardPath)
        {            
            byte[] jsonArr = null;

            using (Stream st = new FileStream(keyCardPath, FileMode.Open, FileAccess.Read))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    int cnt = -1;
                    byte[] buffer = new byte[1024];
                    while ((cnt = st.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        ms.Write(buffer, 0, cnt);
                    }
                    jsonArr = ms.ToArray();
                }
            }
            try
            {
                this.keyCardDO = JsonConvert.DeserializeObject<KeyCardDO>(Encoding.UTF8.GetString(jsonArr));
                if (null == this.keyCardDO)
                {
                    return false;
                }
                // create session key;
                this.keyCardDO.Iv = this.RndMapper.GetRand(this.keyCardDO.RandomIV_Index, 16);
                this.keyCardDO.SessionKey = this.ByteWorker.ExclusiveOr
                (
                    this.RndMapper.GetRand(this.keyCardDO.A_part_Index, 16),
                    this.HexConverter.Hex2Bytes(this.keyCardDO.B_part_HexString)
                );
                return true;
            }
            catch( Exception ex )
            {
                log.Error(ex.StackTrace);
            }

            return false;
        }

        public bool SetKeyFile(string keyFilePath)
        {
            if( null == this.keyCardDO.SessionKey )
            {
                return false;
            }
            // parse key file
            this.mkDic.Clear();
            this.AesCryptor.SetIv( this.keyCardDO.Iv );
            this.AesCryptor.SetKey( this.keyCardDO.SessionKey );
            using( Stream st = new FileStream( keyFilePath, FileMode.Open, FileAccess.Read ) )
            {
                // read header
                byte[] header = new byte[7];
                int cnt = st.Read( header, 0, header.Length );
                if( cnt != header.Length )
                {
                    log.Error( m => m( "Key file header error, read {0} bytes", cnt ) );
                    return false;
                }
                uint totRec = BitConverter.ToUInt16( header, 5 );
                uint recCnt = 0;
                byte[] uid;
                byte[] mk;
                byte[] chk;
                byte[] record = new byte[25];
                while( ( cnt = st.Read( record, 0, record.Length ) ) > 0 )
                {
                    if( cnt != record.Length )
                    {
                        log.Error(m => m("key file body size error after record: {0}", recCnt));
                    }
                    uid = ByteWorker.SubArray(record, 0, 7);
                    mk = ByteWorker.SubArray(record, 7, 16);
                    chk = ByteWorker.SubArray(record, 23, 2);
                    mk = this.AesCryptor.Decrypt(mk);
                    if( this.ByteWorker.AreEqual( chk, this.ByteWorker.SubArray( this.HashWorker.ComputeHash(mk), 0, 2 ) ) )
                    {
                        log.Error(m => m("key file record error after record: {0}", recCnt));
                        return false;
                    }
                    this.mkDic.Add( this.HexConverter.Bytes2Hex(uid), mk);
                    log.Debug(m => m("uid:{0}", this.HexConverter.Bytes2Hex(uid)));
                    recCnt += 1;
                }
                if( recCnt != totRec )
                {
                    log.Error(m => m("key file body record size error expect:{0} but:{1}", totRec, recCnt));
                    return false;
                }
            }
            return true;
        }

        public byte[] GetMasterKey(byte[] uid)
        {
            string uidHex = this.HexConverter.Bytes2Hex(uid);
            if( this.mkDic.ContainsKey( uidHex ) )
            {
                return this.mkDic[uidHex];
            }
            return null;
        }
    }
}
