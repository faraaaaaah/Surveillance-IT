# Accorde le droit "Log on as a batch job" (SeBatchLogonRight) a un compte.
# Necessaire pour qu'une tache planifiee avec identifiants stockes
# (/RU + /RP, ou Register-ScheduledTask -User -Password) puisse s'executer
# meme quand personne n'est connecte a une session interactive.
#
# UTILISATION (a executer EN LOCAL sur la machine cible, ou via
# executer_ps() a distance dans deploiement_distant.py) :
#   .\accorder_droit_batch.ps1 -NomUtilisateur "dell"

param(
    [Parameter(Mandatory=$true)]
    [string]$NomUtilisateur
)

$ErrorActionPreference = "Stop"

$code = @"
using System;
using System.Runtime.InteropServices;

public class LsaHelper {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint LsaOpenPolicy(ref LSA_UNICODE_STRING SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, int DesiredAccess, out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint LsaAddAccountRights(IntPtr PolicyHandle, byte[] AccountSid, LSA_UNICODE_STRING[] UserRights, uint CountOfRights);

    [DllImport("advapi32.dll")]
    static extern uint LsaClose(IntPtr ObjectHandle);

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    static LSA_UNICODE_STRING InitLsaString(string s) {
        var lus = new LSA_UNICODE_STRING();
        if (s == null) s = "";
        lus.Buffer = Marshal.StringToHGlobalUni(s);
        lus.Length = (ushort)(s.Length * 2);
        lus.MaximumLength = (ushort)((s.Length + 1) * 2);
        return lus;
    }

    public static void AjouterDroit(string compte, string droit) {
        var sid = new System.Security.Principal.NTAccount(compte)
            .Translate(typeof(System.Security.Principal.SecurityIdentifier))
            as System.Security.Principal.SecurityIdentifier;
        byte[] sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);

        LSA_OBJECT_ATTRIBUTES oa = new LSA_OBJECT_ATTRIBUTES();
        LSA_UNICODE_STRING systemName = InitLsaString(null);
        IntPtr policyHandle;

        uint res = LsaOpenPolicy(ref systemName, ref oa, 0x00000800 /* POLICY_ALL_ACCESS-ish: create/lookup */, out policyHandle);
        if (res != 0) throw new Exception("LsaOpenPolicy a echoue, code " + res);

        LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
        rights[0] = InitLsaString(droit);

        res = LsaAddAccountRights(policyHandle, sidBytes, rights, 1);
        LsaClose(policyHandle);
        if (res != 0) throw new Exception("LsaAddAccountRights a echoue, code " + res);
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp

[LsaHelper]::AjouterDroit($NomUtilisateur, "SeBatchLogonRight")
Write-Output "OK : droit 'Log on as a batch job' accorde a $NomUtilisateur"