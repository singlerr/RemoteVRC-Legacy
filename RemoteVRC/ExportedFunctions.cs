using System;

namespace RemoteVRC;

public struct ExportedFunction
{
    public string Name;

    public IntPtr Address;

    public ExportedFunction(string name, IntPtr address)
    {
        Name = name;
        Address = address;
    }
}