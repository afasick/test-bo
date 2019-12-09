<?php
 /*********************************************************************************
 *          Filename: OrdersRecord.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "OrdersRecord.php";



check_security(2);

$sOrdersErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Orders":
    Orders_action($sAction);
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
<? Orders_Show() ?>
    
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



function Orders_action($sAction)
{
  global $db;
  global $sForm;
  global $sOrdersErr;
  
  $sParams = "";
  $sActionFileName = "OrdersGrid.php";

  
  $sParams = "?";
  $sParams .= "item_id=" . tourl(get_param("Trn_item_id")) . "&";
  $sParams .= "member_id=" . tourl(get_param("Trn_member_id"));

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName . $sParams); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKorder_id = get_param("PK_order_id");
    
    $sWhere .= "order_id=" . tosql($pPKorder_id, "Number");
    
  }
  
  $fldmember_id = get_param("member_id");
  $flditem_id = get_param("item_id");
  $fldquantity = get_param("quantity");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldmember_id))
      $sOrdersErr .= "The value in field Member is required.<br>";
    
    if(!strlen($flditem_id))
      $sOrdersErr .= "The value in field Item is required.<br>";
    
    if(!strlen($fldquantity))
      $sOrdersErr .= "The value in field Quantity is required.<br>";
    
    if(!is_number($fldmember_id))
      $sOrdersErr .= "The value in field Member is incorrect.<br>";
    
    if(!is_number($flditem_id))
      $sOrdersErr .= "The value in field Item is incorrect.<br>";
    
    if(!is_number($fldquantity))
      $sOrdersErr .= "The value in field Quantity is incorrect.<br>";
    

    if(strlen($sOrdersErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "insert":
      
        $sSQL = "insert into orders (" . 
          "member_id," . 
          "item_id," . 
          "quantity)" . 
          " values (" . 
          tosql($fldmember_id, "Number") . "," .
          tosql($flditem_id, "Number") . "," .
          tosql($fldquantity, "Number") . ")";
    break;
    case "update":
      
        $sSQL = "update orders set " .
          "member_id=" . tosql($fldmember_id, "Number") .
          ",item_id=" . tosql($flditem_id, "Number") .
          ",quantity=" . tosql($fldquantity, "Number");
        $sSQL .= " where " . $sWhere;
    break;
  
    case "delete":
      
        $sSQL = "delete from orders where " . $sWhere;
    break;
  
  }

  if(strlen($sOrdersErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName . $sParams);
  
}



function Orders_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sOrdersErr;

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
   <form method="POST" action="<?= $sFileName ?>" name="Orders">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Orders</font></td></tr>
   <? if ($sOrdersErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sOrdersErr ?></font></td></tr><? } ?>
<? 

  if($sOrdersErr == "")
  {
    //-- Get primary key and form parameters
    $flditem_id = get_param("item_id");
    $fldmember_id = get_param("member_id");
    $fldorder_id = get_param("order_id");
    $Trn_item_id = get_param("item_id");
    $Trn_member_id = get_param("member_id");
    $porder_id = get_param("order_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldmember_id = strip(get_param("member_id"));
    $flditem_id = strip(get_param("item_id"));
    $fldquantity = strip(get_param("quantity"));
    $Trn_item_id = get_param("Trn_item_id");
    $Trn_member_id = get_param("Trn_member_id");
    $porder_id = get_param("PK_order_id");
  }

  
  if( !strlen($porder_id)) $bPK = false;
  
  $sWhere .= "order_id=" . tosql($porder_id, "Number");
  $PK_order_id = $porder_id;

  $sSQL = "select * from orders where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Orders"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldorder_id = $db->f("order_id");
    if($sOrdersErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldmember_id = $db->f("member_id");
      $flditem_id = $db->f("item_id");
      $fldquantity = $db->f("quantity");
    }
  }

  else
  {
    if($sOrdersErr == "")
    {
      $fldorder_id = tohtml(get_param("order_id"));
      $fldmember_id = tohtml(get_param("member_id"));
      $flditem_id = tohtml(get_param("item_id"));
    }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Order</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldorder_id)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Member</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><select name="member_id"><?= get_options("select member_id, member_login from members order by 2",false,true,$fldmember_id);?></select></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Item</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><select name="item_id"><?= get_options("select item_id, name from items order by 2",false,true,$flditem_id);?></select></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Quantity</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="quantity" maxlength="10" value="<?= tohtml($fldquantity) ?>" size="10" ></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Orders"))) { ?>

<? if (!$bPK) { ?>
   <input type="submit" value="Insert" onclick="document.Orders.FormAction.value = 'insert';">
   <input type="hidden" value="insert" name="FormAction"/>
<? } ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Update" onclick="document.Orders.FormAction.value = 'update';">
   
 <? } ?>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Delete" onclick="document.Orders.FormAction.value = 'delete';">
   <? } ?>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.Orders.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="Orders">
  
  <input type="hidden" name="Trn_item_id" value="<?= $Trn_item_id ?>">
  <input type="hidden" name="Trn_member_id" value="<?= $Trn_member_id ?>">
  <input type="hidden" name="PK_order_id" value="<?= $porder_id ?>">  

  </td></tr>
  </form>
  </table>
<?
  
}



?>