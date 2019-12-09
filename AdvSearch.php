<?php
 /*********************************************************************************
 *          Filename: AdvSearch.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "AdvSearch.php";





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
<? Search_Show() ?>
    
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



function Search_Show()
{
  global $styles;
  
  $action_page = "Books.php";

  


    $fldname = strip(get_param("name"));
    $fldauthor = strip(get_param("author"));
    $fldcategory_id = strip(get_param("category_id"));
    $fldpricemin = strip(get_param("pricemin"));
    $fldpricemax = strip(get_param("pricemax"));
  ?>
    <form method="GET" action="<?= $action_page ?>">
    <table style="">
     <tr>
      <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="11"><a name="Search"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Advanced Search</font></a></td>
     </tr>
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Title</font></td>
      <td style="background-color: #FFFFFF; border-width: 1">
         <input type="text" name="name" maxlength="20" value="<?= tohtml($fldname) ?>" size="20" ></td>
     </tr>
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Author</font></td>
      <td style="background-color: #FFFFFF; border-width: 1">
         <input type="text" name="author" maxlength="100" value="<?= tohtml($fldauthor) ?>" size="20" ></td>
     </tr>
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Category</font></td>
      <td style="background-color: #FFFFFF; border-width: 1"><select name="category_id"><?= get_options("select category_id, name from categories order by 2",true,false,$fldcategory_id);?></select></td>
     </tr>
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Price more then</font></td>
      <td style="background-color: #FFFFFF; border-width: 1">
         <input type="text" name="pricemin" maxlength="10" value="<?= tohtml($fldpricemin) ?>" size="10" ></td>
     </tr>
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Price less then</font></td>
      <td style="background-color: #FFFFFF; border-width: 1">
         <input type="text" name="pricemax" maxlength="10" value="<?= tohtml($fldpricemax) ?>" size="10" ></td>
     </tr>
     <tr>
     <td align="right" colspan="3"><input type="submit" value="Search">
     </td>     
    </tr>
     
   </table>
   </form>
<?
  
}
?>