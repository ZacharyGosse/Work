<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Register.aspx.cs" Inherits="SecureLogin.User.Register" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
    
    </div>
        Username<p>
            <asp:TextBox ID="User" runat="server"></asp:TextBox>
        </p>
        <p>
            Password</p>
        <p>
            <asp:TextBox ID="Pass" runat="server"></asp:TextBox>
        </p>
        Confirm Password<p>
            <asp:TextBox ID="PassConf" runat="server"></asp:TextBox>
        </p>
        <asp:Button ID="Create" runat="server" Text="Create User" />
    </form>
</body>
</html>
