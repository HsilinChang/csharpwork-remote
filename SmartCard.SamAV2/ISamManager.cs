using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SmartCard.SamAV2
{
    public interface ISamManager
    {
        /// <summary>
        /// load apdu command file, then connect sam
        /// </summary>
        /// <param name="apduFile">apdu command list file</param>
        /// <returns>true: find sam</returns>
        bool Connect(string apduFile);

        /// <summary>
        /// load apdu command file from resouce, then connect sam
        /// </summary>
        /// <returns>true: find sam</returns>
        bool Connect();

        /// <summary>
        /// Get Sam version info
        /// </summary>
        /// <returns>sam version info</returns>
        byte[] GetVersion();

        /// <summary>
        /// Get Sam UID
        /// </summary>
        /// <returns>uid</returns>
        byte[] GetUid();

        /// <summary>
        /// AuthenticateHost with sam default master key.
        /// ex.SAM AV2 -> key data: all zero, keyNo: 0x00, keyVer: 0x00, TDES 2key/CBC/no padding, iv all zero
        /// </summary>
        /// <param name="authHostDO">auth session info</param>
        /// <returns>true: auth ok!</returns>
        bool AuthenticateHostDefault( AuthHostDO authHostDO );

        /// <summary>
        ///   Change default sam master to transport/perso key entry
        /// </summary>
        /// <param name="keyEntryDO">new key entry</param>
        /// <param name="authHostDO">auth host data</param>
        /// <returns>true: perso ok</returns>
        bool ChangeDefaultMaster( KeyEntryDO keyEntryDO, AuthHostDO authHostDO );

        /// <summary>
        ///   Unlock sam 
        /// </summary>
        /// <param name="keyData"></param>
        /// <param name="keyNo"></param>
        /// <param name="keyVer"></param>
        /// <param name="mode"></param>
        /// <returns>true: unlocked</returns>
        bool Unlock( byte[] keyData, byte keyNo, byte keyVer, byte mode );
        
        /// <summary>
        ///    Authenticate host with default algorithm
        /// </summary>
        /// <param name="keyData">secret key for authenticate</param>
        /// <param name="keyNo">key number</param>
        /// <param name="keyVer">key version</param>
        /// <param name="mode">auth mode</param>
        /// <param name="authHostDO">auth host data object</param>
        /// <returns>true: auth OK!</returns>
        bool AuthenticateHost( byte[] keyData, byte keyNo, byte keyVer, byte mode, AuthHostDO authHostDO );

        /// <summary>
        ///    Authenticate host with aes algorithm
        /// </summary>
        /// <param name="keyData">secret key for authenticate</param>
        /// <param name="keyNo">key number</param>
        /// <param name="keyVer">key version</param>
        /// <param name="mode">auth mode</param>
        /// <param name="authHostDO">auth host data object</param>
        /// <returns>true: auth OK!</returns>
        bool AuthenticateHostAES(byte[] keyData, byte keyNo, byte keyVer, byte mode, AuthHostDO authHostDO);
                
        /// <summary>
        /// Disconnect sam
        /// </summary>
        void DisConnect();

        /// <summary>
        ///   Change key entry with defualt algorithm
        /// </summary>
        /// <param name="keyEntryDO">new key entry data</param>
        /// <param name="authHostDO">auth host info</param>
        /// <returns>true: change key entry ok!</returns>
        bool ChangeKeyEntry( KeyEntryDO keyEntryDO, AuthHostDO authHostDO );

        /// <summary>
        ///   Change key entry with AES algorithm
        /// </summary>
        /// <param name="keyEntryDO">new key entry data</param>
        /// <param name="authHostDO">auth host info</param>
        /// <returns>true: change key entry ok!</returns>
        bool ChangeKeyEntryAES(KeyEntryDO keyEntryDO, AuthHostDO authHostDO);

        /// <summary>
        ///  Get key entry info with specified key number 
        /// </summary>
        /// <param name="keyNo">key number</param>
        /// <returns>key entry of specified key number</returns>
        KeyEntryDO GetKeyEntry(byte keyNo);

        //byte[] DiversePICCKey(byte keyNo, byte keyVer, byte[] divInput);

        byte[] AuthenticatePICC_1(AuthPICCDO authPICCDO ); //( byte keyNo, byte keyVer, byte[] encRndB, byte[] divInput );
        bool AuthenticatePICC_2( AuthPICCDO authPICCDO );
        byte[] Encrypt(byte keyNo, byte keyVer, byte authMode, byte[] iv, byte[] decrypted);

        KUCDO GetKUCEntry(byte kUCNo);
        void ChangeKUCEntry(KUCDO kUCDO, byte[] kxe);

        bool ApplicationExist(byte[] DfAId);

        byte[] GetIssuerInfo(byte keyNo, byte keyVer);

        bool Switch2AV2Mode( byte[] keyData, byte keyVer, AuthHostDO authHostDO );

        bool IsAV2Mode();
    }
}
