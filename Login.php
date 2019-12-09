<?php
 /*********************************************************************************
 *          Filename: Login.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "Login.php";




$sLoginErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Login":
    Login_action($sAction);
  break;
}

?><html>
<head>
<title>Book Store</title>
<meta name="GENERATOR" content="YesSoftware CodeCharge v.1.1.19 using 'PHP.ccp'">
<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="expires" content="0"> 
<meta http-equiv="cache-control" content="no-cache">
</head>
<body style="background-color: #FFFFFF; color: #000000; font-family: Arial, Tahoma, Verdana, Helveticabackground-color: #FFFFFF; color: #000000; font-family: Arial, Tahoma, Verdana, Helvetica">
<center>
 <table>
  <tr>
   <td valign="top">
 <? Menu_Show() ?>
   
   </td>
  </tr>
 </table>
</center>
<hr><center>
 <table>
  <tr>
   
   <td valign="top">
<? Login_Show() ?>
    guest/guest<br>
admin/admin
   </td>
  </tr>
 </table>

<center>
<hr size=1 width=60%>
 <table>
  <tr>
   <td valign="top">
<? Footer_Show() ?>
    </td>
   
  </tr>
 </table>
 
<center><font face="Arial"><small>This dynamic site was generated with <a href="http://www.codecharge.com">CodeCharge</a></small></font></center>
</body>
</html>
<? 



//********************************************************************************


function Login_action($sAction)
{
  global $db;
  global $sLoginErr;


  switch($sAction)
  {
    case "login":
      

      $sLogin = get_param("Login", adText);
      $sPassword = get_param("Password", adText);
      $db->query("SELECT member_id,member_level FROM members WHERE member_login =" . tosql($sLogin,"Text") . " AND member_password=" . tosql($sPassword,"Text") );
      
      if($db->next_record())
      {
        set_session("UserID", $db->f("member_id"));
        set_session("UserRights", $db->f("member_level"));
        $sQueryString = get_param("querystring");
        $sPage = get_param("ret_page");
        if (strlen($sPage))
          header("Location: " . $sPage);
        else
          header("Location: ShoppingCart.php");
      }
      else
        $sLoginErr = "Login or Password is incorrect.";

      

    break;
    case "logout":
      

      session_unregister("UserID");
      session_unregister("UserRights");
      
    break;
  }
}

function Login_Show()
{
  global $sLoginErr;

  global $db;
  global $sFileName;
  global $styles;

  


  $sQueryString = get_param("querystring");
  $sPage = get_param("ret_page");
  $sLogin = get_param("Login", adText);

  
  //-- table header
  ?>
    <table style="">
    <form action="<?= $sFileName ?>" method="POST">
    <input type="hidden" name="FormName" value="Login">

    <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Enter login and password</font></td></tr>
    <? if ($sLoginErr) { ?>
    <tr><td colspan="2" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?= $sLoginErr ?></font></td></tr>
    <? } ?>

  <?

  if(get_session("UserID") == "") //-- user isn't logged in yet
  {
    ?>
      <tr><td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Login</font></td><td style="background-color: #FFFFFF; border-width: 1"><input type="text" name="Login" value="<?= $sLogin ?>" maxlength="20"></td></tr>
      <tr><td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Password</font></td><td style="background-color: #FFFFFF; border-width: 1"><input type="password" name="Password" maxlength="20"></td></tr>
      <tr><td colspan="2">
      <input type="hidden" name="FormAction" value="login">
      <input type="submit" value="Login">
      </td></tr>
    <?
  }
  else //-- user already logged in
  {
    $db->query("SELECT member_login FROM members WHERE member_id=". get_session("UserID"));
    $db->next_record();
    ?>
      <tr><td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"> <?= $db->f("member_login") ?></font>
      <input type="hidden" name="FormAction" value="logout">
      <input type="submit" value="Logout">
      </td></tr>
    <?
  }
  ?><input type="hidden" name="ret_page" value="<?= $sPage ?>"><input type="hidden" name="querystring" value="<?= $sQueryString ?>"></td></tr>
  </form></table>
  <?


}

?>