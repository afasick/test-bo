<?php
 /*********************************************************************************
 *          Filename: ShoppingCartRecord.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "ShoppingCartRecord.php";



check_security(1);

$sShoppingCartRecordErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "ShoppingCartRecord":
    ShoppingCartRecord_action($sAction);
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
<? ShoppingCartRecord_Show() ?>
    <SCRIPT Language="JavaScript">
if (document.forms["ShoppingCartRecord"])
document.ShoppingCartRecord.onsubmit=delconf;
function delconf() {
if (document.ShoppingCartRecord.FormAction.value == 'delete')
  return confirm('Delete record?');
}
</SCRIPT>
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



function ShoppingCartRecord_action($sAction)
{
  global $db;
  global $sForm;
  global $sShoppingCartRecordErr;
  
  $sParams = "";
  $sActionFileName = "ShoppingCart.php";

  

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKorder_id = get_param("PK_order_id");
    
    $sWhere .= "order_id=" . tosql($pPKorder_id, "Number");
    
  }
  
  $fldUserID = get_session("UserID");
  $fldmember_id = get_param("member_id");
  $fldquantity = get_param("quantity");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldquantity))
      $sShoppingCartRecordErr .= "The value in field Quantity is required.<br>";
    
    if(!is_number($fldmember_id))
      $sShoppingCartRecordErr .= "The value in field member_id is incorrect.<br>";
    
    if(!is_number($fldquantity))
      $sShoppingCartRecordErr .= "The value in field Quantity is incorrect.<br>";
    

    if(strlen($sShoppingCartRecordErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "update":
      
        $sSQL = "update orders set " .
          "member_id=" . tosql($fldmember_id, "Number") .
          ",quantity=" . tosql($fldquantity, "Number");
        $sSQL .= " where " . $sWhere;
    break;
  
    case "delete":
      
        $sSQL = "delete from orders where " . $sWhere;
    break;
  
  }

  if(strlen($sShoppingCartRecordErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName);
  
}



function ShoppingCartRecord_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sShoppingCartRecordErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldorder_id = "";
  $fldmember_id = "";
  $flditem_id = "";
  $fldquantity = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="ShoppingCartRecord">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">ShoppingCart</font></td></tr>
   <? if ($sShoppingCartRecordErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sShoppingCartRecordErr ?></font></td></tr><? } ?>
<? 

  if($sShoppingCartRecordErr == "")
  {
    //-- Get primary key and form parameters
    $porder_id = get_param("order_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldorder_id = strip(get_param("order_id"));
    $fldmember_id = strip(get_param("member_id"));
    $fldquantity = strip(get_param("quantity"));
    $porder_id = get_param("PK_order_id");
  }

  
  if( !strlen($porder_id)) $bPK = false;
  
  $sWhere .= "order_id=" . tosql($porder_id, "Number");
  $PK_order_id = $porder_id;

  $sSQL = "select * from orders where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "ShoppingCartRecord"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldorder_id = $db->f("order_id");
    $fldmember_id = $db->f("member_id");
    $flditem_id = $db->f("item_id");
    if($sShoppingCartRecordErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldquantity = $db->f("quantity");
    }
  }

  else
  {
    if($sShoppingCartRecordErr == "")
    {
      $fldmember_id = tohtml(get_session("UserID"));
    }
  }//-- Set lookup fields
  $flditem_id = dlookup("items", "name", "item_id=" . tosql($flditem_id, "Number"));
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Item</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($flditem_id)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Quantity</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="quantity" maxlength="5" value="<?= tohtml($fldquantity) ?>" size="5" ></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="ShoppingCartRecord"))) { ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Update" onclick="document.ShoppingCartRecord.FormAction.value = 'update';">
   
 <? } ?>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Delete" onclick="document.ShoppingCartRecord.FormAction.value = 'delete';">
   <? } ?>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.ShoppingCartRecord.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="ShoppingCartRecord">
  
  <input type="hidden" name="PK_order_id" value="<?= $porder_id ?>">  
  <input type="hidden" name="order_id" value="<?= tohtml($fldorder_id) ?>">
  <input type="hidden" name="member_id" value="<?= tohtml($fldmember_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>