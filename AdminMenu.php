<?php
 /*********************************************************************************
 *          Filename: AdminMenu.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "AdminMenu.php";



check_security(2);


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
<hr>
 <table>
  <tr>
   
   <td valign="top">
<? Form_Show() ?>
    
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


function Form_Show()
{
global $styles;




?>
  <table style="">
  <tr>
    <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Administration Menu</font></td></tr>
  <tr>
  
    <td style="background-color: #FFFFFF; border-width: 1"><a href="MembersGrid.php"><font style="font-size: 10pt; color: #000000">Members</font></a></td></tr><tr>
    <td style="background-color: #FFFFFF; border-width: 1"><a href="OrdersGrid.php"><font style="font-size: 10pt; color: #000000">Orders</font></a></td></tr><tr>
    <td style="background-color: #FFFFFF; border-width: 1"><a href="AdminBooks.php"><font style="font-size: 10pt; color: #000000">Books</font></a></td></tr><tr>
    <td style="background-color: #FFFFFF; border-width: 1"><a href="CategoriesGrid.php"><font style="font-size: 10pt; color: #000000">Categories</font></a></td></tr><tr>
    <td style="background-color: #FFFFFF; border-width: 1"><a href="EditorialsGrid.php"><font style="font-size: 10pt; color: #000000">Editorials</font></a></td></tr><tr>
    <td style="background-color: #FFFFFF; border-width: 1"><a href="EditorialCatGrid.php"><font style="font-size: 10pt; color: #000000">Editorial Categories</font></a></td></tr><tr>
    <td style="background-color: #FFFFFF; border-width: 1"><a href="CardTypesGrid.php"><font style="font-size: 10pt; color: #000000">Card Types</font></a></td>
  </tr>
  </table>
<?

}

?>