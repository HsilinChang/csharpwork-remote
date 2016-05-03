using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SmartCard.SamAV2
{
    public interface IMkSessionManager
    {
        bool SetKeyCard( string keyCardPath );
        bool SetKeyFile( string keyFilePath );
        byte[] GetMasterKey(byte[] uid);
    }
}
