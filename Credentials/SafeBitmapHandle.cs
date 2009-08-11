using System;
using System.Collections.Generic;
using System.Text;
using System.Security;
using System.Security.Permissions;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace Evb.Runtime.InteropServices
{
    [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
    internal sealed class SafeBitmapHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeBitmapHandle() : base(true) { }

        public SafeBitmapHandle(IntPtr preexistingHandle, bool ownsHandle)
            : base(ownsHandle)
        {
            base.SetHandle(preexistingHandle);
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            return NativeMethods.DeleteObject(handle);
        }

        [SuppressUnmanagedCodeSecurity]
        private static class NativeMethods
        {
            [DllImport("GDI32.dll", ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DeleteObject(IntPtr hObject);
        }
    }
}
