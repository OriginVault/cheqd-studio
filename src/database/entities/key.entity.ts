import { BeforeInsert, BeforeUpdate, Column, Entity, JoinColumn, ManyToOne } from 'typeorm';
import { Key } from '@veramo/data-store';
import { CustomerEntity } from './customer.entity.js';
import type { TKeyType } from '@veramo/core-types';
import dotenv from 'dotenv';

dotenv.config();

@Entity('key')
export class KeyEntity extends Key {
	@Column({
		type: 'text',
		nullable: true,
	})
	publicKeyAlias: string;

	@Column({
		type: 'timestamptz',
		nullable: false,
	})
	createdAt!: Date;

	@Column({
		type: 'timestamptz',
		nullable: true,
	})
	updatedAt!: Date;

	@BeforeInsert()
	setCreatedAt() {
		this.createdAt = new Date();
		if (this.publicKeyAlias) {
			this.meta = { ...this.meta, alias: this.publicKeyAlias };
		}
	}

	@BeforeUpdate()
	setUpdateAt() {
		this.updatedAt = new Date();
		if (this.publicKeyAlias) {
			this.meta = { ...this.meta, alias: this.publicKeyAlias };
		}
	}

	@ManyToOne(() => CustomerEntity, (customer) => customer.customerId, { onDelete: 'CASCADE' })
	@JoinColumn({ name: 'customerId' })
	customer!: CustomerEntity;

	constructor(kid: string, type: TKeyType, publicKeyHex: string) {
		super();
		this.kid = kid;
		this.type = type;
		this.publicKeyHex = publicKeyHex;
		this.publicKeyAlias = '';
		this.meta = {};
		this.kms = 'local';
	}
}
