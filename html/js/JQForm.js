/**
 * Created by 圣烽 on 2018/1/8.
 */
!(function ($) {
    var globalOptions={};
    $.fn.form = function (options) {
        var that = $(this);
        globalOptions  = $.extend({},{
            url: that.attr("action"),
            method: that.attr("method"),
            dataType: 'json',
            async: true,
            success: function (data) {
            },
            error: function (data) {
            }
        }, options);

        submit(that)
        return this;
    }

    var submit = function (that) {
        that.submit(function() { // 提交时验证
            $.ajax($.extend({}, globalOptions,{ data: that.serialize()}));
            return false;
        })
    }

})(window.jQuery)

