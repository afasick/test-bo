<?php
 /*********************************************************************************
 *          Filename: ShoppingCart.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "ShoppingCart.php";



check_security(1);

$sMemberErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Member":
    Member_action($sAction);
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
<hr>
 <table>
  <tr>
   
   <td valign="top">
<? Member_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Items_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Total_Show() ?>
    
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


function Items_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sItemsErr; //-- error string

  
  $bReq = true; //-- there are required parameters

//-- table header
?>
     <table style="">
      <tr>
       <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="6"><a name="Items"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Items</font></a></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Details</td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Order #</td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Item</td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Price</td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Quantity</td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Total</td>
      </tr>
<?

  $sWhere = "";
  
  //-- Check UserID parameter and create a valid sql for where clause
  
  $pUserID = get_session("UserID");
  if(is_number($pUserID) && strlen($pUserID))
    $pUserID = round($pUserID);
  else 
    $pUserID = "";
  if(strlen($pUserID)) 
  {
    $HasParam = true;
    $sWhere .= "member_id=" . $pUserID;
  }
  else
    $bReq = false;
  //-- populate arrays for list of values
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " AND (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "SELECT order_id, name, price, quantity, member_id, quantity*price as sub_total FROM items, orders WHERE orders.item_id=items.item_id" . $sWhere . " ORDER BY order_id";
  

  //-- insert button
  
//-- required parameters
  if(!$bReq)
  {
    ?>
     <tr>
      <td colspan="6" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records></font></td>
     </tr>
    </table>
    <?
    return;
  }


  //-- do SQL query
  $db->query($sSQL);
  
  $is_next_record=false;

  //-- show records
  if($db->next_record())
  {
    //-- default values
    $sField1= "Details";

    //-- display rows
    do
    {
      //-- retrieve data from the record
      $fldorder_id = $db->f("order_id");
      $flditem_id = $db->f("name");
      $fldprice = $db->f("price");
      $fldquantity = $db->f("quantity");
      $fldsub_total = $db->f("sub_total");
      $fldField1= "Details";

      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><a href="ShoppingCartRecord.php?order_id=<?= tourl($db->f("order_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldField1) ?></font></a>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldorder_id)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($flditem_id)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldprice)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldquantity)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldsub_total)?>&nbsp;</font></td>
      </tr>
    <?
    $is_next_record = @$db->next_record();
    } while($is_next_record );
  }
  else //-- there are no records
  {
  //$db->num_rows() == 0 || ($iPage - 1)*$RecordsPerPage >= $db->num_rows())
    ?>
      <tr><td colspan="6" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records</font></td></tr>


      </table>
    <?
    return;
  }

 

  //-- the end of the last row and the end of the table
  ?>
    </table>
  <?

 
}


function Total_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sTotalErr; //-- error string

  
  $bReq = true; //-- there are required parameters

//-- table header
?>
     <table style="">
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Total</td>
      </tr>
<?

  $sWhere = "";
  
  //-- Check UserID parameter and create a valid sql for where clause
  
  $pUserID = get_session("UserID");
  if(is_number($pUserID) && strlen($pUserID))
    $pUserID = round($pUserID);
  else 
    $pUserID = "";
  if(strlen($pUserID)) 
  {
    $HasParam = true;
    $sWhere .= "member_id=" . $pUserID;
  }
  else
    $bReq = false;
  //-- populate arrays for list of values
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " AND (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "SELECT member_id, sum(quantity*price) as sub_total FROM items, orders WHERE orders.item_id=items.item_id" . $sWhere . " GROUP BY member_id";
  

  //-- insert button
  
//-- required parameters
  if(!$bReq)
  {
    ?>
     <tr>
      <td colspan="1" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records></font></td>
     </tr>
    </table>
    <?
    return;
  }


  //-- do SQL query
  $db->query($sSQL);
  
  $is_next_record=false;

  //-- show records
  if($db->next_record())
  {
    //-- default values
    

    //-- display rows
    do
    {
      //-- retrieve data from the record
      $fldsub_total = $db->f("sub_total");

      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldsub_total)?>&nbsp;</font></td>
      </tr>
    <?
    $is_next_record = @$db->next_record();
    } while($is_next_record );
  }
  else //-- there are no records
  {
  //$db->num_rows() == 0 || ($iPage - 1)*$RecordsPerPage >= $db->num_rows())
    ?>
      <tr><td colspan="1" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records</font></td></tr>


      </table>
    <?
    return;
  }

 

  //-- the end of the last row and the end of the table
  ?>
    </table>
  <?

 
}



function Member_action($sAction)
{
  global $db;
  global $sForm;
  global $sMemberErr;
  
  $sParams = "";
  $sActionFileName = "AdminMenu.php";

  
  $sParams = "?";
  $sParams .= "UserID=" . tourl(get_param("Trn_UserID"));

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName . $sParams); 

  
  $fldUserID = get_session("UserID");

  //-- Create SQL statement
  $sSQL = "";
  
  if(strlen($sMemberErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName . $sParams);
  
}



function Member_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sMemberErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldmember_id = "";
  $fldmember_login = "";
  $fldname = "";
  $fldlast_name = "";
  $fldaddress = "";
  $fldemail = "";
  $fldphone = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Member">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">User Information</font></td></tr>
   <? if ($sMemberErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sMemberErr ?></font></td></tr><? } ?>
<? 

  if($sMemberErr == "")
  {
    //-- Get primary key and form parameters
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldmember_id = strip(get_param("member_id"));
  }

  
  $pmember_id = get_session("UserID");
  if( !strlen($pmember_id)) $bPK = false;
  
  $sWhere .= "member_id=" . tosql($pmember_id, "Number");
  $PK_member_id = $pmember_id;

  $sSQL = "select * from members where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Member"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldmember_id = $db->f("member_id");
    $fldmember_login = $db->f("member_login");
    $fldname = $db->f("first_name");
    $fldlast_name = $db->f("last_name");
    $fldaddress = $db->f("address");
    $fldemail = $db->f("email");
    $fldphone = $db->f("phone");
  }

  else
  {
    if($sMemberErr == "")
    {
      $fldmember_id = tohtml(get_session("UserID"));
    }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Login</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><a href="MyInfo.php?<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldmember_login) ?></font></a>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">First Name</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldname)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Last Name</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldlast_name)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Address</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldaddress)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Email</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldemail)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Phone</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldphone)?>&nbsp;</font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Member"))) { ?>

<? } ?>

 
   <input type="hidden" name="FormName" value="Member">
  
  <input type="hidden" name="Trn_UserID" value="<?= $Trn_UserID ?>">
  <input type="hidden" name="PK_member_id" value="<?= $pmember_id ?>">  
  <input type="hidden" name="member_id" value="<?= tohtml($fldmember_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>