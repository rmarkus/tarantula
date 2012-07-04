/*
 * Ext JS Library 1.1
 * Copyright(c) 2006-2007, Ext JS, LLC.
 * licensing@extjs.com
 * 
 * http://www.extjs.com/license
 */


Ext.util.MixedCollection=function(_1,_2){this.items=[];this.map={};this.keys=[];this.length=0;this.addEvents({"clear":true,"add":true,"replace":true,"remove":true,"sort":true});this.allowFunctions=_1===true;if(_2){this.getKey=_2;}Ext.util.MixedCollection.superclass.constructor.call(this);};Ext.extend(Ext.util.MixedCollection,Ext.util.Observable,{allowFunctions:false,add:function(_3,o){if(arguments.length==1){o=arguments[0];_3=this.getKey(o);}if(typeof _3=="undefined"||_3===null){this.length++;this.items.push(o);this.keys.push(null);}else{var _5=this.map[_3];if(_5){return this.replace(_3,o);}this.length++;this.items.push(o);this.map[_3]=o;this.keys.push(_3);}this.fireEvent("add",this.length-1,o,_3);return o;},getKey:function(o){return o.id;},replace:function(_7,o){if(arguments.length==1){o=arguments[0];_7=this.getKey(o);}var _9=this.item(_7);if(typeof _7=="undefined"||_7===null||typeof _9=="undefined"){return this.add(_7,o);}var _a=this.indexOfKey(_7);this.items[_a]=o;this.map[_7]=o;this.fireEvent("replace",_7,_9,o);return o;},addAll:function(_b){if(arguments.length>1||_b instanceof Array){var _c=arguments.length>1?arguments:_b;for(var i=0,_e=_c.length;i<_e;i++){this.add(_c[i]);}}else{for(var _f in _b){if(this.allowFunctions||typeof _b[_f]!="function"){this.add(_f,_b[_f]);}}}},each:function(fn,_11){var _12=[].concat(this.items);for(var i=0,len=_12.length;i<len;i++){if(fn.call(_11||_12[i],_12[i],i,len)===false){break;}}},eachKey:function(fn,_16){for(var i=0,len=this.keys.length;i<len;i++){fn.call(_16||window,this.keys[i],this.items[i],i,len);}},find:function(fn,_1a){for(var i=0,len=this.items.length;i<len;i++){if(fn.call(_1a||window,this.items[i],this.keys[i])){return this.items[i];}}return null;},insert:function(_1d,key,o){if(arguments.length==2){o=arguments[1];key=this.getKey(o);}if(_1d>=this.length){return this.add(key,o);}this.length++;this.items.splice(_1d,0,o);if(typeof key!="undefined"&&key!=null){this.map[key]=o;}this.keys.splice(_1d,0,key);this.fireEvent("add",_1d,o,key);return o;},remove:function(o){return this.removeAt(this.indexOf(o));},removeAt:function(_21){if(_21<this.length&&_21>=0){this.length--;var o=this.items[_21];this.items.splice(_21,1);var key=this.keys[_21];if(typeof key!="undefined"){delete this.map[key];}this.keys.splice(_21,1);this.fireEvent("remove",o,key);}},removeKey:function(key){return this.removeAt(this.indexOfKey(key));},getCount:function(){return this.length;},indexOf:function(o){if(!this.items.indexOf){for(var i=0,len=this.items.length;i<len;i++){if(this.items[i]==o){return i;}}return-1;}else{return this.items.indexOf(o);}},indexOfKey:function(key){if(!this.keys.indexOf){for(var i=0,len=this.keys.length;i<len;i++){if(this.keys[i]==key){return i;}}return-1;}else{return this.keys.indexOf(key);}},item:function(key){var _2c=typeof this.map[key]!="undefined"?this.map[key]:this.items[key];return typeof _2c!="function"||this.allowFunctions?_2c:null;},itemAt:function(_2d){return this.items[_2d];},key:function(key){return this.map[key];},contains:function(o){return this.indexOf(o)!=-1;},containsKey:function(key){return typeof this.map[key]!="undefined";},clear:function(){this.length=0;this.items=[];this.keys=[];this.map={};this.fireEvent("clear");},first:function(){return this.items[0];},last:function(){return this.items[this.length-1];},_sort:function(_31,dir,fn){var dsc=String(dir).toUpperCase()=="DESC"?-1:1;fn=fn||function(a,b){return a-b;};var c=[],k=this.keys,_39=this.items;for(var i=0,len=_39.length;i<len;i++){c[c.length]={key:k[i],value:_39[i],index:i};}c.sort(function(a,b){var v=fn(a[_31],b[_31])*dsc;if(v==0){v=(a.index<b.index?-1:1);}return v;});for(var i=0,len=c.length;i<len;i++){_39[i]=c[i].value;k[i]=c[i].key;}this.fireEvent("sort",this);},sort:function(dir,fn){this._sort("value",dir,fn);},keySort:function(dir,fn){this._sort("key",dir,fn||function(a,b){return String(a).toUpperCase()-String(b).toUpperCase();});},getRange:function(_45,end){var _47=this.items;if(_47.length<1){return[];}_45=_45||0;end=Math.min(typeof end=="undefined"?this.length-1:end,this.length-1);var r=[];if(_45<=end){for(var i=_45;i<=end;i++){r[r.length]=_47[i];}}else{for(var i=_45;i>=end;i--){r[r.length]=_47[i];}}return r;},filter:function(_4a,_4b){if(!_4b.exec){_4b=String(_4b);if(_4b.length==0){return this.clone();}_4b=new RegExp("^"+Ext.escapeRe(_4b),"i");}return this.filterBy(function(o){return o&&_4b.test(o[_4a]);});},filterBy:function(fn,_4e){var r=new Ext.util.MixedCollection();r.getKey=this.getKey;var k=this.keys,it=this.items;for(var i=0,len=it.length;i<len;i++){if(fn.call(_4e||this,it[i],k[i])){r.add(k[i],it[i]);}}return r;},clone:function(){var r=new Ext.util.MixedCollection();var k=this.keys,it=this.items;for(var i=0,len=it.length;i<len;i++){r.add(k[i],it[i]);}r.getKey=this.getKey;return r;}});Ext.util.MixedCollection.prototype.get=Ext.util.MixedCollection.prototype.item;