//
//  ViewController.swift
//  swift
//
//  Created by june on 26/01/2019.
//  Copyright © 2019 june. All rights reserved.
//

import UIKit
import Tink

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        tinkExample()
    }
    
    
    func tinkExample()  {
        
        let targetText = "hello".data(using: .utf8)
        let addedText = "world".data(using: .utf8)
        
        print("targetText:\(String(data: targetText!, encoding: .utf8))")
        
        
        
        //1.config
        let config = try? TINKAllConfig()
        if !(((try? TINKConfig.register(config!)) != nil)) {
            // handle error.
        }
        //2. Get a handle to the key material.
        let tpl = try! TINKAeadKeyTemplate(keyTemplate: .TINKAes128Gcm)
        let keysetHandle = try! TINKKeysetHandle(keyTemplate: tpl)

        //3. Get the primitive.
        let aead: TINKAead? = try? TINKAeadFactory.primitive(with: keysetHandle)
        
        
        
        // 4. encrypto
        let ciphertext: Data? = try! aead?.encrypt(targetText!, withAdditionalData: addedText)
        
        print("targetText:\(String(describing: ciphertext?.base64EncodedString()))")
        
        // 5. decrypt
        let originText: Data? = try! aead?.decrypt(ciphertext!, withAdditionalData: addedText)
        
        print("targetText:\(String(describing: String(data: originText!, encoding: .utf8)))")
    }
    
    
}

