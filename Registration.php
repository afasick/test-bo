<?php
 /*********************************************************************************
 *          Filename: Registration.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "Registration.php";




$sRegErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Reg":
    Reg_action($sAction);
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
<? Reg_Show() ?>
    
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



function Reg_action($sAction)
{
  global $db;
  global $sForm;
  global $sRegErr;
  
  $sParams = "";
  $sActionFileName = "Default.php";

  

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName); 

  
  $fldmember_login = get_param("member_login");
  $fldmember_password = get_param("member_password");
  $fldmember_password2 = get_param("member_password2");
  $fldfirst_name = get_param("first_name");
  $fldlast_name = get_param("last_name");
  $fldemail = get_param("email");
  $fldaddress = get_param("address");
  $fldphone = get_param("phone");
  $fldcard_type_id = get_param("card_type_id");
  $fldcard_number = get_param("card_number");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldmember_login))
      $sRegErr .= "The value in field Login* is required.<br>";
    
    if(!strlen($fldmember_password))
      $sRegErr .= "The value in field Password* is required.<br>";
    
    if(!strlen($fldmember_password2))
      $sRegErr .= "The value in field Confirm Password* is required.<br>";
    
    if(!strlen($fldfirst_name))
      $sRegErr .= "The value in field First Name* is required.<br>";
    
    if(!strlen($fldlast_name))
      $sRegErr .= "The value in field Last Name* is required.<br>";
    
    if(!strlen($fldemail))
      $sRegErr .= "The value in field Email* is required.<br>";
    
    if(!is_number($fldcard_type_id))
      $sRegErr .= "The value in field Credit Card Type is incorrect.<br>";
    
    if(strlen($fldmember_login) )
    {
      $iCount = 0;

      if($sAction == "insert")
        $iCount = dlookup("members", "count(*)", "member_login=" . tosql($fldmember_login, "Text"));
      else if($sAction == "update")
        $iCount = dlookup("members", "count(*)", "member_login=" . tosql($fldmember_login, "Text") . " and not(" . $sWhere . ")");
  
      if($iCount > 0)
        $sRegErr .= "The value in field Login* is already in database.<br>";
    }                                                                               
    
if (get_param("member_password") != get_param("member_password2"))
  $sRegErr .= "\nPassword and Confirm Password fields don't match";

    if(strlen($sRegErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "insert":
      
        $sSQL = "insert into members (" . 
          "member_login," . 
          "member_password," . 
          "first_name," . 
          "last_name," . 
          "email," . 
          "address," . 
          "phone," . 
          "card_type_id," . 
          "card_number)" . 
          " values (" . 
          tosql($fldmember_login, "Text") . "," .
          tosql($fldmember_password, "Text") . "," .
          tosql($fldfirst_name, "Text") . "," .
          tosql($fldlast_name, "Text") . "," .
          tosql($fldemail, "Text") . "," .
          tosql($fldaddress, "Text") . "," .
          tosql($fldphone, "Text") . "," .
          tosql($fldcard_type_id, "Number") . "," .
          tosql($fldcard_number, "Text") . ")";
    break;
  }

  if(strlen($sRegErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName);
  
}



function Reg_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sRegErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldmember_id = "";
  $fldmember_login = "";
  $fldmember_password = "";
  $fldfirst_name = "";
  $fldlast_name = "";
  $fldemail = "";
  $fldaddress = "";
  $fldphone = "";
  $fldcard_type_id = "";
  $fldcard_number = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Reg">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Registration</font></td></tr>
   <? if ($sRegErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sRegErr ?></font></td></tr><? } ?>
<? 

  if($sRegErr == "")
  {
    //-- Get primary key and form parameters
    $pmember_id = get_param("member_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldmember_id = strip(get_param("member_id"));
    $fldmember_login = strip(get_param("member_login"));
    $fldmember_password = strip(get_param("member_password"));
    $fldfirst_name = strip(get_param("first_name"));
    $fldlast_name = strip(get_param("last_name"));
    $fldemail = strip(get_param("email"));
    $fldaddress = strip(get_param("address"));
    $fldphone = strip(get_param("phone"));
    $fldcard_type_id = strip(get_param("card_type_id"));
    $fldcard_number = strip(get_param("card_number"));
    $pmember_id = get_param("PK_member_id");
  }

  
  $fldmember_password2 = get_param("member_password2");
  if( !strlen($pmember_id)) $bPK = false;
  
  $sWhere .= "member_id=" . tosql($pmember_id, "Number");
  $PK_member_id = $pmember_id;

  $sSQL = "select * from members where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Reg"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldmember_id = $db->f("member_id");
    if($sRegErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldmember_login = $db->f("member_login");
      $fldmember_password = $db->f("member_password");
      $fldfirst_name = $db->f("first_name");
      $fldlast_name = $db->f("last_name");
      $fldemail = $db->f("email");
      $fldaddress = $db->f("address");
      $fldphone = $db->f("phone");
      $fldcard_type_id = $db->f("card_type_id");
      $fldcard_number = $db->f("card_number");
    }
  }

  else
  {
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Login*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="member_login" maxlength="20" value="<?= tohtml($fldmember_login) ?>" size="20" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Password*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="password" name="member_password" maxlength="20" value="<?= tohtml($fldmember_password) ?>" size="20" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Confirm Password*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="password" name="member_password2" maxlength="20" value="<?= tohtml($fldmember_password2) ?>" size="20" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">First Name*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="first_name" maxlength="50" value="<?= tohtml($fldfirst_name) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Last Name*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="last_name" maxlength="50" value="<?= tohtml($fldlast_name) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Email*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="email" maxlength="50" value="<?= tohtml($fldemail) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Address</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="address" maxlength="50" value="<?= tohtml($fldaddress) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Phone</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="phone" maxlength="50" value="<?= tohtml($fldphone) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Credit Card Type</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><select name="card_type_id"><?= get_options("select card_type_id, name from card_types order by 2",false,false,$fldcard_type_id);?></select></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Credit Card Number</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="card_number" maxlength="20" value="<?= tohtml($fldcard_number) ?>" size="20" ></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Reg"))) { ?>

<? if (!$bPK) { ?>
   <input type="submit" value="Register" onclick="document.Reg.FormAction.value = 'insert';">
   <input type="hidden" value="insert" name="FormAction"/>
<? } ?>

<? } else { ?>
  <input type="hidden" value="" name="FormAction"/>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.Reg.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="Reg">
  
  <input type="hidden" name="PK_member_id" value="<?= $pmember_id ?>">  
  <input type="hidden" name="member_id" value="<?= tohtml($fldmember_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>