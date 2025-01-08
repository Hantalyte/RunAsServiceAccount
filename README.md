# RunAsServiceAccount

RunAsServiceAccount is a Windows API program that receives the name of a service and then launches a command prompt process with the service account of the given service. 

## How It Works

Service accounts are tricky. They are non-interactive accounts, meaning they are not designed for direct user logins or interactions. Due to this, the functions "LogonUserW" and "CreateProcessAsUserW" do not work with service accounts. While one theoretically could utilize the access token of the running service, which contains the service account, it is impractical to do this on account of the overall less control that the calling program has, even potentially requiring it to forcibly launch the service. Therefore, it is best to create a new token from the ground up using the undocumented function "NtCreateToken" proceeded by "CreateProcessWithTokenW."

The problem with "NtCreateToken" is that it requires the calling process to have the privilege "SeCreateTokenPrivilege," which is not normally available for enablement to normal accounts, including administrators. The simplest way to bypass this is to create a temporary account, which will be deleted after usage, that will have this privilege available to it. The privilege is added using "LsaAddAccountRights." The reason for creating a temporary account is that adding the privilege to the current user may pose future security risks.

The SID of the service accounts needs to be known to create the access token. This program finds this through another undocumented function: "RtlCreateServiceSid." This function is interesting in that, so long as its arguments are all valid, it will provide a valid SID regardless, even if the service does not exist. As for creating the token, it is entirely up to the developer to determine how powerful the launched process will or will not be. In this program, it is a very high-level process, with it being afforded every single possible privilege and on a system integrity level.

Here is unofficial documentation for the two mentioned functions:
- [NtCreateToken](https://ntdoc.m417z.com/ntcreatetoken)
- [RtlCreateServiceSid](https://ntdoc.m417z.com/rtlcreateservicesid)

## Installation and Compilation Information

The program was written in C and compiled using Visual Studio 2022. To run it, simply download and launch the "RunAsServiceAccount.exe" file from the repository. Note that it must be run with administrative privileges.

## Usage

While the program itself can be used to launch command prompt as a service account at the user's discretion, its main value comes with its source code. How the program works can be applied to many different circumstances.

## Contact Details and Bug Reporting

If you have any questions, feedback, or encounter any issues with the program, feel free to reach out to me.
- **Email**: [hantalyte@proton.me](mailto:hantalyte@proton.me)
  
If you come across any bugs or unexpected behavior while using the program, please report them by opening an issue on GitHub:
- [Report a Bug](https://github.com/Hantalyte/RunAsServiceAccount/issues/new)
