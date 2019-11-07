import {boops} from './test2.js'

boops();

const gg = 9;
function foo (t) {
    var a = 55;
    var b = 33;
    var c = {
        d: true,
        e: 'hello',
        f: 34.55,
    };

    function noob() {
        console.log('f;asdsad`')
        console.log(a);
        console.log(t);
        console.log('supsups')
        console.log('ubgasdsad')
    }
    noob();
}

function bar() {
    foo(3);
    console.log('asdsad');
    console.log('about to throw!');
    try {
        throw new Error('whoops');
    }
    catch (e) {
    }
}

class Blub {
    peeps = 3;
    jib() {
        console.log(this);
        bar();
    }
}

var blub = new Blub();
blub.jib();
